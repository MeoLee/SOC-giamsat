[CmdletBinding()]
param(
    [ValidateSet('Cpu', 'Cuda')][string]$Mode = 'Cpu',
    [string]$VenvPath = '',
    [string]$PythonPath = '',
    [switch]$PlanOnly,
    [switch]$RunChecks
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = $PSScriptRoot
if (-not $VenvPath) {
    $VenvPath = Join-Path (Split-Path -Parent $project) ('.venv-ai04-' + $Mode.ToLowerInvariant())
}
$VenvPath = [System.IO.Path]::GetFullPath($VenvPath)
$windowsPlatform = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$venvPython = if ($windowsPlatform) { Join-Path $VenvPath 'Scripts\python.exe' } else { Join-Path $VenvPath 'bin/python' }
$pythonPrefix = @()
if (-not $PythonPath) {
    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($null -eq $launcher) { throw 'Python 3.12 launcher missing. Install Python 3.12 or supply -PythonPath PATH_TO_PYTHON.' }
    $PythonPath = $launcher.Source
    $pythonPrefix = @('-3.12')
}
$index = if ($Mode -eq 'Cuda') { 'https://download.pytorch.org/whl/cu126' } else { 'https://download.pytorch.org/whl/cpu' }
$cache = Join-Path (Split-Path -Parent $VenvPath) '.cache-ai04'
$steps = @(
    [pscustomobject]@{Exe=$PythonPath; Args=@($pythonPrefix) + @('-c', 'import sys; assert sys.version_info[:2] == (3,12), sys.version; print(sys.version)')},
    [pscustomobject]@{Exe=$PythonPath; Args=@($pythonPrefix) + @('-m', 'venv', $VenvPath)},
    [pscustomobject]@{Exe=$venvPython; Args=@('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--cache-dir', $cache, 'torch==2.11.0', '--index-url', $index)},
    [pscustomobject]@{Exe=$venvPython; Args=@('-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--cache-dir', $cache, '-r', (Join-Path $project 'requirements-tested.txt'))},
    [pscustomobject]@{Exe=$venvPython; Args=@('-c', $(if ($Mode -eq 'Cuda') {
        'import torch; print(torch.__version__, torch.version.cuda); assert torch.cuda.is_available(), "CUDA unavailable: inspect NVIDIA driver and selected interpreter"; print(torch.cuda.get_device_name(0))'
    } else { 'import torch; print(torch.__version__); assert torch.version.cuda is None, "Expected CPU-only torch"' }))},
    [pscustomobject]@{Exe=$venvPython; Args=@((Join-Path $project 'lab_doctor.py'), '--config', (Join-Path $project 'live-config.json'))}
)
if ($RunChecks) { $steps += [pscustomobject]@{Exe=$venvPython; Args=@((Join-Path $project 'run_checks.py'))} }
Write-Output ('PROJECT: ' + $project)
Write-Output ('PYTHON: ' + $venvPython)
Write-Output ('MODE: ' + $Mode + '; model, dataset and existing lab services are separate')
if ($PlanOnly) {
    foreach ($step in $steps) { Write-Output ($step.Exe + ' ' + ($step.Args -join ' ')) }
    return
}
$previousMatplotlib = [Environment]::GetEnvironmentVariable('MPLCONFIGDIR', 'Process')
try {
    [Environment]::SetEnvironmentVariable('MPLCONFIGDIR', (Join-Path $cache 'matplotlib'), 'Process')
    foreach ($step in $steps) {
        & $step.Exe @($step.Args)
        if ($LASTEXITCODE -ne 0) { throw ('Step failed with exit=' + $LASTEXITCODE + ': ' + $step.Exe) }
    }
    Write-Output 'AI_ENVIRONMENT_CHECKED'
    Write-Output 'No traffic generation, model retraining, model promotion or Docker service installation was performed.'
} finally {
    [Environment]::SetEnvironmentVariable('MPLCONFIGDIR', $previousMatplotlib, 'Process')
}
