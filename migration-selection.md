# Opt-in newest multi-ref context

In the deployment corpus configuration (the file passed with `--config`), set:

```yaml
migration:
  multi_ref_policy: newest
```

Default `error` is unchanged. This option addresses **unqualified nonhistorical companions** beside multiple audited refs. It uses valid recorded baseline-audit dates, not file mtime, current-projection date, Git commit dates or branch sorting. Date-only metadata is compared at midnight UTC as an ordering convention, not a recovered checkout timestamp. Missing/invalid dates block; newest dates tied across distinct refs block. A tie within one ref is reported with a deterministic audit source path.

Explicit metadata/directory release refs are retained. Independent named branch audits remain selected rather than overwritten or excluded. Report, triage and Ledger artifacts are never reassigned across historical baselines by this fallback; they still need an exact ref or explicit baseline binding. Repository disagreements still fail.

Successful decisions record `context_selection` with policy, recorded audit date, source audit path and selected ref. Where the artifact contract has a subject binding, the companion uses that selected audit subject/run. Source artifacts and historical signatures/events are never changed.

This is deliberately narrower than collapsing all repository history into a single newest snapshot. Many real release audits share the same date; those require explicit selection rather than guessing a branch. Preview all remaining issues before any database run. No claim is made that the 77 existing ambiguities disappear automatically.
