[CmdletBinding()]
param(
    [string]$Model = 'E:\SOC-Lab\AI\runs\mlp04-quality-20261019-232507',
    [string]$OutputRoot = 'E:\SOC-Lab\AI\monitor-sessions',
    [string]$PythonPath = '',
    [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$caseName = 'monitor-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
$startArgs = @{ Model=$Model; OutputRoot=$OutputRoot; Case=$caseName }
if ($PythonPath) { $startArgs.PythonPath = $PythonPath }
if ($PlanOnly) { $startArgs.PlanOnly = $true }
Write-Output 'Open Kali Bash in another terminal and type the scenario commands. No SESSION/operator input is needed.'
Write-Output 'Wait for READY before generating traffic. Ctrl+C ends capture and preserves raw evidence.'
& (Join-Path $PSScriptRoot 'Start-Wazuh-Live.ps1') @startArgs
