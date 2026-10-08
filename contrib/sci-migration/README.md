# SCI post-native migration adapter (review contribution)

This optional, application-specific contribution bridges **accepted native Engine/Contracts artifacts** into SCI's application tables and existing S3 resolver. It is separate from native migration logic and the performance PR. It does not replace Shaun's CLI, bypass its quarantine, invent products/refs, restamp identities, or replay historical Ledger events through a service actor.

## Included

- `native_sci_shim.py`: exact-byte S3 conditional publication/readback and reference registration into existing native bindings; canonical current-snapshot selection; exact source-qualified triage parent preservation; SCI inventory/scan/triage/publication/provenance projections with disabled scan policies.
- `native_partial.py`: accepted-only reconciliation gates, durable file quarantine, hash-bound reviewed input overlays and per-ownership projection selection.
- `project_native.py`: explicit approved post-native execution with namespace Secret-derived DB/S3 access, verified RDS TLS, native decisions/result/issues hashes, scoped target checks and bounded product-repo groups.
- `job.yaml`: suspended, tokenless, nonroot, read-only-filesystem illustrative Job with separate corpus/evidence read-only mounts and persistent output. Image/PVC/approval placeholders are intentionally not runnable or deploy-approved. Bake reviewed adapters into the digest-pinned image; provide a scoped DNS/DB/S3 egress policy with labels that do not match application Services.
- Synthetic unit tests for current-state selection, legacy exact refs, chronology, queue/quarantine behavior and revised-input hashing.

## Native/app boundaries

Run native `traust_engine.corpus.migrate_cli` first. Provision SCI public migrations separately using the reviewed app revision and operator role. Both native and application schemas must match the pinned runtime. The adapter **does not create/reset/drop databases or schemas**, create DB roles, sign/restamp Ledger layers, enable workers, or copy human history into local UUID layers.

Native output must have complete diagnostics, exact loaded projection/source/row reconciliation, and no systemic/unclassified failures. `allow_record_failures` is an explicit operator policy for accepted-only publication. Failed/unresolved sources remain in output quarantine; historical artifacts are untouched. Never use the incident-specific repaired-reconciliation proof to bypass these checks.

Target approval file requires exact `engine_version`, `contracts_version`, `ledger_version`, `source_revision`, `namespace`, `db_host`, `db_name`, `bucket`, `bucket_owner`, `region`, `decisions_sha256`, and `native_output_sha256` for migration-result.json/issues.jsonl; plus nonempty approval/freeze/recovery references. Those references are operator evidence, not automatic verification of a cluster UID, paused writers or backup. The Job has no Kubernetes token or cloud snapshot privileges. Original verification keys are still required for historical signature trust.

Runtime imports need pinned boto3/botocore, psycopg and the native Engine/Contracts/Ledger dependencies; no runtime package downloads. Credentials are mounted via `sci-database` and `sci-object-store`; passwords never enter Git, image layers or command arguments.

```sh
python project_native.py --source /corpus --native-output /evidence/native-run \
  --target /approval/target.json --report /reports/approved-run
```

Use a new report directory on exact replay, with the same source/native decision hashes. Existing publication/result receipt identity, ownership, timestamps and pointers must agree. Conflicting prior application state is rejected, not overwritten. The contribution uses an unambiguous `product-repo:<UUID>` inventory scope rather than the earlier `product@ref` concatenation; **it will refuse existing legacy-scope inventories** unless an explicit reviewed migration is performed. It does not silently alter the live Mig-test data model.

## Selection safeguards

Choose one cumulative-role or `-findings-current.json` report per product-repo/run, otherwise one baseline. Multiple current roots stay blocked. Preserve historical triage against its exact named baseline (`file.json#finding-ID`) and require recorded chronology; do not transfer it to a newer current state by ordinal/fuzzy title. If necessary retain the older scan separately, while preventing it from changing current-ref selection. Missing snapshot commit, parent-reference ambiguity or invalid chronology remain exclusions.

## Validation status and required review

The related prototype ran on Mig-test with real PostgreSQL and verified S3 readback. This portable extraction strengthens path/replay/scope checks and **has not been deployed or PostgreSQL/S3 end-to-end tested**. Its current unit suite is evidence of logical regression coverage, not production certification. Keep this PR draft until the portable version has tests for interrupted publication, wrong pointers, tampered receipts, mixed-product scopes and synthetic live integration/replay.

SCI resolver adoption is PR #177; anchored Ledger read/product-ref metadata is SCI #179 and Console #170; slash-bearing native DB read compatibility is Ledger #71. Review/rebase onto those interfaces before claiming UI parity. Write/signing/pipeline routing and full source-to-UI comparison remain separate acceptance gates.

Not included: destructive Mig-test reset, old custom transformation/import engine, signing-key/credential/kubeconfig files, private corpus reports/manifests, or incident-specific `resume_native.py`/reconciliation bypass. The Bubble Tea monitor and fidelity comparison outputs remain local operational tooling and may be contributed separately; they are not native ingestion adapters.
