# 0.4.6 chain investigation — 2026-10-20

- Add a separate Wazuh Chain Investigation dashboard with full-text row
  expansion, source/account/timing context, unique evidence counts and score
  components; preserve the existing five dashboard objects and user layout.
- Select latest source-event time at microsecond precision so revisions sharing
  a Wazuh timestamp millisecond cannot arbitrarily show an earlier stage.
- Add opt-in fixed benign shell/HTTP-file probes, scoped to a dedicated lab
  account. Extend one SSH case only with matching source/target/account/port,
  event-time window and token; require verified transfer bytes/hash.
- Add chain-extended, bounded one-file server lifecycle and raw endpoint/auth/
  server trace checks. No SSH/PAM/rule changes, inferred C2 or general audit claim.
- Document Attack Flow, ATT&CK technique sources and local scoring policy;
  preserve MLP weights/thresholds and the existing capped operational score.

# 0.4.5 chain dashboard — 2026-10-20

- Add stable chain display IDs, observed-stage summaries, ATT&CK candidates and
  explicit base/recon-bonus scoring fields to correlation events.
- Preserve existing risk policy, evidence-linked graphs, account/source/time
  scoping and the distinction between observations and confirmed compromise.
- Ship additive OpenSearch Dashboards saved objects: latest revision per chain,
  transition history and policy explanation; use existing Wazuh alert fields
  without index mapping changes, global defaults or new credentials.
- Keep existing model weights, operating threshold, feature contract, Wazuh XML
  IDs and training engine. No execution/transfer/C2 stage inferred from SSH login.

# 0.4.3 operational Wazuh realtime — 2026-10-19

- Publish sensor signatures without waiting for completed-flow MLP inference;
  optionally publish auth, HTTP and below-threshold flow observations.
- Add explainable operational risk, evidence-linked chain graphs and separate
  telemetry-counter warnings; preserve hypothesis/compromise boundaries.
- Add manager alert/index-response trace tooling, bounded private-Docker lab
  scenarios, a Windows Live helper and an installation/acceptance runbook.
- Validate eleven bridge event types before manager restart; preserve private
  persistent config backups and require the updated rule marker for publication.
- No new model training, changed feature contract or automatic response.

# 0.4.2 dashboard Quality controls — 2026-10-19

- Pass local-loss-fraction, patience and skip-baseline from the HTML form to the
  CLI worker, validate settings and persist them in the dashboard session.
- Restore run metadata when selecting/resuming; legacy runs retain legacy defaults.
- Verify a real HTTP Train action through a CPU worker and exported Quality bundle.
- Document Windows GUI training and provide a patch relative to 0.4.1.
- No change to model weights, datasets, feature contract or training engine.

# 0.4.1 packaging/test hotfix — 2026-10-19

- Restore the dashboard HTML asset omitted from the original0.4 release ZIP.
- Make context byte-offset regression test exercise explicit LF and CRLF bytes.
- Package all tracked source assets, require dashboard HTML, and run the complete
  suite from extracted full and repaired ZIPs before releasing.
- No model/training/inference policy, feature contract, data or environment change.

# 0.4.0-research — 2026-10-19

- Add independently evidenced local-session preparation and scoped SSH labeling
  for fresh training without the historical CICIDS cache.
- Validate prepared arrays and full bundle contracts; retain legacy checkpoint
  policy on resume and version validation-only quality selection on new runs.
- Compare saved baseline/candidate bundles on the same held-out sessions with
  coverage, uncertainty, source isolation and explicit evidence limitations.
- Add bounded local shadow context for distinct ports and optional Apache request
  rates, with raw-reference error journals and degraded processing states.
- Add installation, training, research and real-lab scenario guides, a deterministic
  offline replay suite, and a tested CPU environment setup script.
- No real-user weights retraining, model promotion or live lab deployment.

# 0.3.0-candidate.1 — 2026-10-19

- Consolidate the uploaded active Lab A source with Quality and Web utilities.
- Preserve Live v0.4/UI, Windows I/O snapshots, checkpoints and the MLP24 contract.
- Validate source/asset identity and Windows filenames; retain decoded Wazuh EVE
  fields, integer IDs and evidence byte offsets.
- Add read-only lab diagnostics, cross-poll replay regressions and a full test runner.
- This is a source candidate; no real model retraining, promotion or lab deployment.

# 0.2.0

- Rolling atomic full-training checkpoint and graceful pause/restore mid-epoch.
- Optimizer, RNG, sample offset, history, best state and stopping-state restoration.
- Persisted workflow status for CLI and localhost dashboard.
- Local UI controls prepare, start, pause, resume and export verification.
- File-only Matplotlib loss/validation plots every epoch, numbered PNG/SVG reports.
- Dataset preparation and final confusion/F1/attack-metric charts.
- Safe checkpoint loading, dataset hash checks and local HTTP action token.
- Export contract/model features remain compatible with v0.1.

At the time of v0.2.0, live ingestion, correlation and Grafana were planned.
See the candidate notes and Vietnamese integration guide for current scope.
