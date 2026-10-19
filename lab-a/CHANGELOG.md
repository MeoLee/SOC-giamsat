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
