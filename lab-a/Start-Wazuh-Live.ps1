[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Model,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')][string]$Case = 'wazuh-live-01',
    [string]$OutputRoot = 'E:\SOC-Lab\AI\wazuh-tests',
    [string]$PythonPath = '',
    [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$project = $PSScriptRoot
if (-not $PythonPath) {
    $PythonPath = Join-Path (Split-Path -Parent $project) '.venv-ai04-cpu\Scripts\python.exe'
}
$config = Join-Path $project 'live-config.json'
$destination = Join-Path $OutputRoot $Case
$liveArgs = @('-u', (Join-Path $project 'lab_live.py'), '--model', $Model,
    '--config', $config, '--output-dir', $destination,
    '--publish-wazuh', '--publish-observations', '--summary-seconds', '1',
    '--interval', '1', '--grace', '90', '--heartbeat-seconds', '10')
Write-Output ('CASE OUTPUT: ' + $destination)
Write-Output 'Auth/sensor evidence is sent on collection; MLP waits for completed flows.'
if ($PlanOnly) {
    Write-Output ($PythonPath + ' ' + ($liveArgs -join ' '))
    return
}
if (-not (Test-Path -LiteralPath $PythonPath)) { throw 'Inference interpreter missing.' }
if (-not (Test-Path -LiteralPath (Join-Path $Model 'model.json'))) { throw 'Model directory missing.' }
Push-Location $project
try {
    & $PythonPath (Join-Path $project 'lab_doctor.py') --config $config --model $Model --runtime --bridge
    if ($LASTEXITCODE -ne 0) { throw 'Doctor failed. Inspect output before running scenarios.' }
    & $PythonPath @liveArgs
    if ($LASTEXITCODE -ne 0) { throw 'Live ended with errors or incomplete processing. Preserve this session and its outbox.' }
} finally {
    Pop-Location
}
