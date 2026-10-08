"""Post-native SCI projection adapter; never reset or bootstrap a target database."""

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path

from native_partial import partial_native_result, project_successful_groups, save_quarantine
from native_sci_shim import project, register_evidence


def publish(source, output, target, report):
    from importlib.metadata import version

    import boto3
    import psycopg

    for name in ("engine", "contracts", "ledger"):
        if version("traust-" + name) != target[name + "_version"]:
            raise ValueError("native dependency approval mismatch")
    for name in ("approval_reference", "freeze_reference", "recovery_reference"):
        if not target.get(name):
            raise ValueError("operator approval gate missing")
    for name, expected in (
        ("POD_NAMESPACE", target["namespace"]),
        ("DB_HOST", target["db_host"]),
        ("DB_NAME", target["db_name"]),
        ("MINIO_BUCKET_REPORTS", target["bucket"]),
    ):
        if os.environ.get(name) != expected:
            raise ValueError("mounted target identity mismatch")
    if os.environ.get("MINIO_USE_SSL") != "true":
        raise ValueError("object storage TLS required")
    ca = Path(os.environ["RDS_CA_FILE"])
    if not ca.is_file() or not ca.read_bytes():
        raise ValueError("verified RDS CA required")
    port = int(os.environ["DB_PORT"])
    if not 0 < port < 65536:
        raise ValueError("invalid database port")
    raw = (output / "decisions.jsonl").read_bytes()
    approval = hashlib.sha256(raw).hexdigest()
    if approval != target["decisions_sha256"]:
        raise ValueError("native decision approval differs")
    for name in ("migration-result.json", "issues.jsonl"):
        if (
            hashlib.sha256((output / name).read_bytes()).hexdigest()
            != target["native_output_sha256"][name]
        ):
            raise ValueError("native reconciliation evidence approval differs")
    decisions, issues = partial_native_result(output)
    if issues and not target.get("allow_record_failures"):
        raise ValueError("explicit accepted-only approval required")
    groups = collections.defaultdict(list)
    for row in decisions:
        if row.get("decision") in ("ingested", "already_bound"):
            groups[row.get("product_repo_id")].append(row)
    quarantine = report
    quarantine.mkdir(mode=0o700, parents=True, exist_ok=False)
    save_quarantine(quarantine, decisions, issues)
    objects = boto3.client(
        "s3",
        region_name=target["region"],
        aws_access_key_id=os.environ["MINIO_ACCESS_KEY"],
        aws_secret_access_key=os.environ["MINIO_SECRET_KEY"],
    )
    objects.head_bucket(Bucket=target["bucket"], ExpectedBucketOwner=target["bucket_owner"])
    completed = rejected = 0
    with psycopg.connect(
        host=target["db_host"],
        port=port,
        dbname=target["db_name"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        sslmode="verify-full",
        sslrootcert=str(ca),
        connect_timeout=15,
        autocommit=True,
    ) as connection:
        identity = connection.execute(
            "SELECT current_database(),ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()"
        ).fetchone()
        if identity != (target["db_name"], True):
            raise ValueError("connected database identity/TLS mismatch")
        for index, rows in enumerate(groups.values()):
            accepted = register_evidence(connection, objects, target, source, rows)
            records, failures = project_successful_groups(
                accepted, quarantine / f"projection-{index:06d}.jsonl"
            )
            rejected += len(failures)
            for record in records:
                completed += project(connection, [record], target["source_revision"], approval)
            if index % 100 == 0:
                print(json.dumps({"groups": index, "projected": completed}), flush=True)
    summary = {"projected": completed, "projection_quarantine": rejected, "reset": False}
    (quarantine / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    (quarantine / "summary.json").chmod(0o600)
    print(json.dumps(summary), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--native-output", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        publish(
            args.source.resolve(),
            args.native_output.resolve(),
            json.loads(args.target.read_text()),
            args.report.resolve(),
        )
    except Exception:
        raise SystemExit(
            "SCI adapter failed; inspect private evidence without exposing credentials"
        ) from None
