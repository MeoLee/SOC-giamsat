# Lab A 0.4 research

Start with [the Vietnamese release guide](README-START-VI.md),
[installation and training](docs/INSTALL-TRAIN-VI.md), and
[test scenarios](docs/SCENARIOS-VI.md). This package contains source and verified
software workflows; it does not contain a newly validated real-world model.

The original v0.2 core documentation is retained below for historical context.

## SOC AI v0.2 — checkpoint, workflow dashboard and numbered reports

Windows / VS Code / Python 3.12 / PyTorch 2.11.0 CUDA. The feature/model contract
is unchanged from v0.1: six-class experimental completed-flow baseline, 24 features,
internal grouped split, portable CPU inference. This release adds resumable
training, a local UI and PNG/SVG report snapshots.

## Quick start on your machine

Extract `SOC-AI-v0.2` into E:\SOC-Lab\AI, then open that folder in VS Code.
Interpreter: E:\SOC-Lab\AI\.venv\Scripts\python.exe.

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.2'
$python = 'E:\SOC-Lab\AI\.venv\Scripts\python.exe'
& $python -m pip install 'matplotlib>=3.9,<4'
if ($LASTEXITCODE -ne 0) { throw 'Matplotlib installation failed' }
& $python -m unittest discover -s tests -v
if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
& $python -m soc_ai dashboard --root 'E:\SOC-Lab\AI' --port 8765
```

Open http://127.0.0.1:8765. Keep the dashboard terminal open.
The dashboard is local-only, requires no account, internet API or frontend CDN.
It launches Python workers through a structured subprocess command, not a shell.

## UI workflow

1. Session setup: inspect cohort, prepared folder, run folder and train settings.
2. Prepare: only if prepared data does not already exist. Use a NEW output folder.
3. Start training: leave Run folder blank for a timestamped new run.
4. Live status: current stage, epoch, batch, loss, last validation F1, checkpoint time.
5. Pause & save: wait until status becomes Paused and message confirms saved state.
6. Resume checkpoint: select the previous run from Recent runs, then Resume.
7. Reports: curves after every epoch, test report, numbered downloadable PNG/SVG.
8. Verify export: run CPU golden-vector verification after training completes.

Preparation output from v0.1 remains usable; no new PCAP/label matching is needed.
If using old prepared-v01, preparation charts may be absent; training reports still
work. Resume uses settings stored in the checkpoint, not edited form fields.
Use New run to clear the selected run folder before starting a new experiment.
Closing only the browser tab does NOT stop training. Closing the server terminal
with Ctrl+C requests a graceful pause from a worker started by that server.
Always confirm Paused before shutting down; a force-killed process only has the
last periodic checkpoint, not necessarily the last batch.

The workflow sidebar shows prepare, load, train, epoch validation, holdout test,
linear comparison, export/verify, and two PLANNED future stages: independent lab
experiment and auth/network correlation + Grafana. Those integrations are not
implemented by this release. The sidebar does not claim they are already complete.

## CLI alternative

Prepare only if needed:

```powershell
$cohort = 'E:\SOC-Lab\dataset\normalized\CICIDS2017\experimental-cohort-20261011-184306\cohort.jsonl'
$prepared = 'E:\SOC-Lab\AI\prepared-v01'
& $python -u -m soc_ai prepare --cohort "$cohort" --output "$prepared" --experimental-labels
```

New training:

```powershell
$run = 'E:\SOC-Lab\AI\runs\mlp-v02-' + (Get-Date -Format 'yyyyMMdd-HHmmss')
& $python -u -m soc_ai train --prepared "$prepared" --output "$run" --device cuda --epochs 20 --batch-size 2048 --checkpoint-seconds 30
```

Press Ctrl+C once, then wait for `TRAINING_PAUSED`. Python defers the stop until
a batch/poll boundary so it does not save a partially applied optimizer update.
After restart, re-open PowerShell and point to the SAME run directory:

```powershell
Set-Location 'E:\SOC-Lab\AI\SOC-AI-v0.2'
$python = 'E:\SOC-Lab\AI\.venv\Scripts\python.exe'
& $python -u -m soc_ai train --resume 'E:\SOC-Lab\AI\runs\YOUR_PREVIOUS_RUN'
```

The saved prepared path is restored from the checkpoint. Keep drive letter E:
and those files available. No environment activation or Execution Policy change
is required. Do not launch concurrent resume workers for the same run directory.
A completed run cannot be resumed as a new experiment; choose a new output folder.

## What a checkpoint stores

`RUN/checkpoints/latest.pt` is saved initially, at most every configured 30 seconds
at a completed-batch boundary, at each completed epoch and on a graceful pause.
It stores current model weights, optimizer moments/steps, epoch, sample offset,
global step, accumulated weighted loss, validation history, best model state,
early-stopping state, Python/NumPy/Torch CPU/CUDA RNG state, train configuration
and dataset/feature hashes. Epoch permutations are regenerated deterministically
from seed+epoch; offset skips already committed batches.

The checkpoint is written to a temporary file, flushed, fsynced, then atomically
replaced. A failed replacement preserves the previous checkpoint. Unexpected
power loss/hardware or filesystem corruption can still damage files; no claim
is made of immunity. Sudden interruption rolls back to the last intact checkpoint,
so some work since that save may repeat. This is one rolling training checkpoint,
not a routine backup/cleanup of your dataset.

Loading uses `torch.load(weights_only=True)` with tensors and primitive state.
Resume refuses a changed dataset, feature contract or PyTorch version. Use the
same Python environment and device type. Resume across GPU hardware/driver changes
is not guaranteed bit-for-bit reproducible. Mid-epoch stop/resume was verified
with identical CPU weights and losses versus an uninterrupted test run.

If paused during test/baseline/export, neural training is already checkpointed;
resume repeats those post-training stages from their beginning. The CPU linear
baseline itself is not checkpointed. Preparation is not resumable in the middle;
its completed cache can be reused. v0.1 runs lack optimizer/resume state, so they
cannot be retroactively resumed; their exported inference bundles still work.

## Numbered chart files

Preparation: PREPARED/charts/001_preparation_splits.png and
002_preparation_classes.png (each also exported as SVG).
Training: RUN/charts/001_epoch_0001_loss.png,
002_epoch_0001_validation.png, 003_epoch_0002_loss.png,
004_epoch_0002_validation.png, etc.
Final test charts follow the last completed epoch numbers: test confusion matrix,
class F1 comparison and attack precision/recall/FPR/PR-AUC. `charts/index.json`
lists files and numbers. Numbering is stable when resumed, not duplicated by
session restart. Loss snapshots show the cumulative train/validation trajectory;
validation snapshots also show per-class F1 for that epoch. Interrupted partial
epochs appear in live progress, not as completed-epoch chart snapshots.

Train and validation loss use the same class-weighted cross-entropy definition.
Charts use the file-only Agg backend and need no desktop graphics window. The UI
also draws learning curves from saved history and refreshes automatically.

## Export and later lab connection

Bundle files remain model-weights.npz, preprocessor.json, features.json,
model.json, metrics.json, golden vectors and requirements-lock.txt. Keep them
alongside each other; weights.npz uses numeric arrays without Python pickle.
Prediction: `python -m soc_ai predict --model RUN --verify-only --device cpu`.
Raw EVE batch prediction uses the same normalizer/features as training.

Dockerfile is a starting point for CPU batch inference. It is not an executed
live deployment. Future lab data should enter through an EVE/log collector and
versioned normalizer, then model inference/correlation, then alert storage and
Grafana. Checkpoints belong to the training service; inference containers only
need the smaller exported model bundle. Do not expose this local training UI to
the lab network as an inference endpoint. A separate inference/collector service
will be added for that experiment.

## Research scope and limits

The 549,816 selected cohort labels remain provisional. Stage --experimental-labels
acknowledges this; source labels stay unchanged. Tuple-group 70/15/15 hashing keeps
same/reverse connection tuples together but is NOT chronological or independent
of attack episodes. IP, port, rules, paths, IDs, time, day and evidence tier are
not model features. App protocol/state are network features. Full counters become
available at EVE emission; predictions are not backdated to flow start.

The normalizer supports staging/EVE/completed-flow wrappers, not arbitrary public
CSV formats. Missing counters fail rather than becoming zero. Single-packet,
zero-duration and tcp_reuse inputs are out_of_training_scope in inference, not
BENIGN. Auth-window detection and attack-chain reconstruction are later modules.
Internal metrics are not deployment accuracy; independent lab sessions remain
necessary. Softmax scores are uncalibrated; the alert threshold targets observed
validation BENIGN FPR about 1%, without a guarantee in the lab.
