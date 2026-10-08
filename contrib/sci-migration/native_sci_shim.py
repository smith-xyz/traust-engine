import collections
import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

NAMESPACE = uuid.UUID("c581afed-79c0-42a0-9500-c025d883ecbd")


def identity(*parts):
    return str(uuid.uuid5(NAMESPACE, json.dumps(parts, separators=(",", ":"))))


def completed(document, family):
    value = (
        document.get("triage_completed")
        if family == "triage"
        else document.get("metadata", {}).get("date")
    )
    if not isinstance(value, str):
        raise ValueError("recorded completion date required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def validate_references(parent, child, parent_path=None, child_path=None):
    ids = {finding["id"] for finding in parent.get("findings", [])}
    references = []
    for finding in child.get("findings", []):
        reference = finding.get("orig_id") or finding.get("original_id")
        source = finding.get("source")
        if isinstance(source, str) and "#" in source:
            filename, fragment = source.rsplit("#", 1)
            if parent_path is None or child_path is None:
                raise ValueError("source-qualified triage requires exact baseline path evidence")
            else:
                named = Path(filename)
                expected = Path(parent_path)
                sibling = Path(child_path).parent / named
                if (
                    named.is_absolute()
                    or ".." in named.parts
                    or not (
                        named.as_posix() == expected.as_posix()
                        or sibling.as_posix() == expected.as_posix()
                    )
                ):
                    raise ValueError("triage source names a different baseline report")
                if reference and reference != fragment:
                    raise ValueError(
                        "triage explicit and source-qualified finding identities disagree"
                    )
                reference = fragment
        if not isinstance(reference, str) or reference not in ids:
            raise ValueError("triage requires exact unique parent finding references")
        references.append(reference)
    if len(set(references)) != len(references):
        raise ValueError("triage references duplicate baseline findings")
    return references


def register_evidence(connection, objects, target, source, decisions):
    from botocore.exceptions import ClientError
    from traust_contracts.v1.storage import Store

    store = Store(connection)
    registered = []
    for row in decisions:
        if (
            row.get("decision") not in ("ingested", "already_bound")
            or row.get("namespace") != "traust_storage"
        ):
            continue
        relative = Path(row["source_file"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe accepted artifact path")
        path = source / relative
        if not path.resolve().is_relative_to(source.resolve()):
            raise ValueError("source escapes corpus")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != row["source_digest"]:
            raise ValueError("native source hash changed")
        matches = connection.execute(
            "SELECT binding_id FROM traust_storage.artifact_binding WHERE "
            "artifact_digest=%s AND artifact_name=%s",
            (digest, row["artifact"]),
        ).fetchall()
        connection.rollback()
        records = [store.get_binding(match[0]) for match in matches]
        connection.rollback()
        records = [
            record
            for record in records
            if record.binding.product_repo_id == row.get("product_repo_id")
        ]
        if len(records) != 1:
            raise ValueError("native accepted binding is absent or ambiguous")
        record = records[0]
        key = "artifacts/sha256/" + digest
        reference = "s3://" + target["bucket"] + "/" + key
        try:
            objects.put_object(
                Bucket=target["bucket"],
                Key=key,
                Body=raw,
                IfNoneMatch="*",
                ExpectedBucketOwner=target["bucket_owner"],
            )
        except ClientError as error:
            if error.response["Error"]["Code"] not in ("PreconditionFailed", "412"):
                raise
        response = objects.get_object(
            Bucket=target["bucket"], Key=key, ExpectedBucketOwner=target["bucket_owner"]
        )
        try:
            if response["Body"].read() != raw:
                raise ValueError("S3 exact-byte readback differs")
        finally:
            response["Body"].close()
        saved = store.ingest(row["artifact"], raw, record.binding, references=[reference])
        if saved.binding_id != record.binding_id or not saved.already_bound:
            raise ValueError("shim created a new native binding")
        registered.append((row, record, json.loads(raw), reference))
    return registered


def projection_rows(registered):
    reports = collections.defaultdict(list)
    triages = []
    for row, record, document, reference in registered:
        if row["artifact"] == "report":
            reports[(record.binding.product_repo_id, record.binding.run_id)].append(
                (row, record, document, reference)
            )
        elif row["artifact"] == "triage":
            triages.append((row, record, document, reference))
    selected = {}
    for key, candidates in reports.items():
        current = [
            item
            for item in candidates
            if item[1].binding.role == "cumulative"
            or item[0]["source_file"].endswith("-findings-current.json")
        ]
        chosen = current or candidates
        if len(chosen) != 1:
            raise ValueError("explicit current-report chain selection required")
        selected[key] = chosen[0]
    output = []
    for item in selected.values():
        row, record, document, reference = item
        stamp = completed(document, "report")
        anchor = record.binding.product_repo_id
        if not anchor:
            raise ValueError("registered product_repo required")
        ids = [finding.get("id") for finding in document.get("findings", [])]
        if any(not value for value in ids) or len(set(ids)) != len(ids):
            raise ValueError("report finding IDs must be unique")
        output.append(
            {
                "kind": "report",
                "inventory_id": identity("native-inventory", anchor),
                "result_id": identity("native-scan", record.binding_id),
                "scan_id": identity("native-scan", record.binding_id),
                "anchor": anchor,
                "binding": record,
                "document": document,
                "completed": stamp,
                "path": row["source_file"],
                "reference": reference,
            }
        )
    for row, record, document, reference in triages:
        key = (record.binding.product_repo_id, record.binding.run_id)
        if key not in selected:
            raise ValueError("triage has no selected native report")
        parent = selected[key]
        qualified = {
            f["source"].rsplit("#", 1)[0]
            for f in document.get("findings", [])
            if isinstance(f.get("source"), str) and "#" in f["source"]
        }
        if qualified:
            matches = []
            for candidate in reports[key]:
                try:
                    validate_references(
                        candidate[2], document, candidate[0]["source_file"], row["source_file"]
                    )
                except ValueError:
                    continue
                matches.append(candidate)
            if len(matches) != 1:
                raise ValueError(
                    "triage baseline path/IDs do not resolve uniquely among retained reports"
                )
            parent = matches[0]
        validate_references(parent[2], document, parent[0]["source_file"], row["source_file"])
        stamp = completed(document, "triage")
        if stamp < completed(parent[2], "report"):
            raise ValueError("triage precedes its exact referenced baseline")
        parent_scan = identity("native-scan", parent[1].binding_id)
        if not any(existing["result_id"] == parent_scan for existing in output):
            if completed(parent[2], "report") >= completed(selected[key][2], "report"):
                raise ValueError(
                    "referenced baseline is not older than canonical current snapshot; "
                    "selection policy unresolved"
                )
            output.extend(projection_rows([parent]))
        output.append(
            {
                "kind": "triage",
                "inventory_id": identity("native-inventory", key[0]),
                "result_id": identity("native-triage", record.binding_id),
                "scan_id": parent_scan,
                "anchor": key[0],
                "binding": record,
                "document": document,
                "completed": stamp,
                "path": row["source_file"],
                "reference": reference,
            }
        )
    return output


def project(connection, records, source_revision, approval_hash):
    import psycopg.types.json

    for row in records:
        record = row["binding"]
        binding = record.binding
        document = row["document"]
        counts = collections.Counter(
            str(f.get("severity", "")).lower() for f in document.get("findings", [])
        )
        provenance = {
            "kind": row["kind"],
            "path": row["path"],
            "source_revision": source_revision,
            "manifest_sha256": approval_hash,
            "product_repo_id": row["anchor"],
            "native_binding_id": record.binding_id,
            "projection": "native-selected-current",
            "date_only_is_midnight_convention": len(
                str(document.get("metadata", {}).get("date", ""))
            )
            == 10,
        }
        with connection.transaction():
            cursor = connection.cursor()
            cursor.execute(
                "SELECT repo.repo_url,p.slug,pr.ref FROM traust_storage.product_repo "
                "pr JOIN traust_storage.repo repo ON repo.repo_id=pr.repo_id JOIN "
                "traust_storage.product p ON p.product_id=pr.product_id WHERE "
                "pr.product_repo_id=%s",
                (row["anchor"],),
            )
            registered = cursor.fetchone()
            if not registered:
                raise ValueError("projection ownership not registered")
            repo, _product, ref = registered
            scope = "product-repo:" + row["anchor"]
            cursor.execute(
                "SELECT repo_url,source,cluster_id,namespace FROM inventory_items WHERE id=%s",
                (row["inventory_id"],),
            )
            existing_inventory = cursor.fetchone()
            if existing_inventory and existing_inventory != (
                repo,
                "manual",
                "native-corpus",
                scope,
            ):
                raise ValueError(
                    "existing SCI inventory scope differs; explicit legacy migration required"
                )
            cursor.execute(
                "SELECT "
                "payload_sha256,provenance,inventory_item_id::text,scan_result_id::text"
                ",completed_at FROM historical_artifact_imports WHERE result_id=%s AND "
                "artifact_kind=%s",
                (row["result_id"], row["kind"]),
            )
            previous = cursor.fetchone()
            if previous:
                if previous != (
                    record.artifact_digest,
                    provenance,
                    row["inventory_id"],
                    row["scan_id"],
                    row["completed"],
                ):
                    raise ValueError("SCI projection receipt conflict")
                cursor.execute(
                    "SELECT "
                    "binding_id,source_sha256,s3_url,state,inventory_item_id::text,scan_res"
                    "ult_id::text,scope_id,subject_id,run_id FROM artifact_ingestions "
                    "WHERE result_id=%s AND artifact_kind=%s",
                    (row["result_id"], row["kind"]),
                )
                if cursor.fetchone() != (
                    record.binding_id,
                    record.artifact_digest,
                    row["reference"],
                    "published",
                    row["inventory_id"],
                    row["scan_id"],
                    binding.scope_id,
                    binding.subject_id,
                    binding.run_id,
                ):
                    raise ValueError("existing SCI publication differs from native binding")
                table = "scan_results" if row["kind"] == "report" else "triage_results"
                cursor.execute(
                    "SELECT status,completed_at,inventory_item_id::text FROM "
                    + table
                    + " WHERE id=%s",
                    (row["result_id"],),
                )
                if cursor.fetchone() != ("completed", row["completed"], row["inventory_id"]):
                    raise ValueError("existing SCI result chronology differs")
                continue
            cursor.execute(
                "INSERT INTO "
                "inventory_items(id,repo_url,source,cluster_id,namespace,status,first_s"
                "een_at,last_seen_at,created_at,updated_at) "
                "VALUES(%s,%s,'manual','native-corpus',%s,'active',%s,%s,%s,%s) ON "
                "CONFLICT(id) DO NOTHING",
                (
                    row["inventory_id"],
                    repo,
                    scope,
                    row["completed"],
                    row["completed"],
                    row["completed"],
                    row["completed"],
                ),
            )
            if row["kind"] == "report":
                commit = binding.commit_sha or document.get("metadata", {}).get("commit")
                if not isinstance(commit, str) or not commit:
                    raise ValueError("snapshot commit must be recorded, not inferred")
                cursor.execute(
                    "INSERT INTO "
                    "scan_results(id,inventory_item_id,scanned_ref,requested_ref,status,rep"
                    "ort,findings_count,critical_count,high_count,medium_count,low_count,in"
                    "fo_count,created_at,completed_at,harness_version) "
                    "VALUES(%s,%s,%s,NULLIF(%s,''),'completed',NULL,%s,%s,%s,%s,%s,%s,%s,%s"
                    ",%s)",
                    (
                        row["result_id"],
                        row["inventory_id"],
                        commit,
                        ref,
                        len(document.get("findings", [])),
                        counts["critical"],
                        counts["high"],
                        counts["medium"],
                        counts["low"],
                        counts["informational"],
                        row["completed"],
                        row["completed"],
                        document.get("metadata", {}).get("harness_version"),
                    ),
                )
                cursor.execute(
                    "UPDATE inventory_items SET current_ref=%s,last_scanned_ref=%s WHERE "
                    "id=%s AND NOT EXISTS(SELECT 1 FROM scan_results WHERE "
                    "inventory_item_id=%s AND status='completed' AND completed_at>%s)",
                    (commit, commit, row["inventory_id"], row["inventory_id"], row["completed"]),
                )
                cursor.execute(
                    "INSERT INTO scan_policies(inventory_item_id,enabled,auto_triage) "
                    "VALUES(%s,false,false) ON CONFLICT DO NOTHING",
                    (row["inventory_id"],),
                )
            else:
                verdicts = collections.Counter(
                    f.get("verdict") for f in document.get("findings", [])
                )
                cursor.execute(
                    "INSERT INTO "
                    "triage_results(id,inventory_item_id,scan_result_id,status,triage_repor"
                    "t,true_positive_count,false_positive_count,hardening_count,undetermine"
                    "d_count,created_at,completed_at) "
                    "VALUES(%s,%s,%s,'completed',NULL,%s,%s,%s,%s,%s,%s)",
                    (
                        row["result_id"],
                        row["inventory_id"],
                        row["scan_id"],
                        verdicts["true_positive"],
                        verdicts["false_positive"],
                        verdicts["hardening"],
                        verdicts["undetermined"],
                        row["completed"],
                        row["completed"],
                    ),
                )
            cursor.execute(
                "INSERT INTO "
                "historical_artifact_imports(result_id,artifact_kind,inventory_item_id,"
                "scan_result_id,payload_sha256,provenance,completed_at) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (
                    row["result_id"],
                    row["kind"],
                    row["inventory_id"],
                    row["scan_id"],
                    record.artifact_digest,
                    psycopg.types.json.Jsonb(provenance),
                    row["completed"],
                ),
            )
            cursor.execute(
                "INSERT INTO "
                "artifact_ingestions(result_id,artifact_kind,inventory_item_id,scan_res"
                "ult_id,source_sha256,scope_id,subject_id,run_id,binding_id,state,publi"
                "shed_at,s3_url) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'published',now(),%s)",
                (
                    row["result_id"],
                    row["kind"],
                    row["inventory_id"],
                    row["scan_id"],
                    record.artifact_digest,
                    binding.scope_id,
                    binding.subject_id,
                    binding.run_id,
                    record.binding_id,
                    row["reference"],
                ),
            )
    return len(records)
