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
