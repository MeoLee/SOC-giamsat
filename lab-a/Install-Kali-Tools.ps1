[CmdletBinding()]
param([string]$Container = 'kali-attacker')
$ErrorActionPreference = 'Stop'
if ($Container -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') { throw 'Container name invalid.' }
docker exec --user 0 $Container mkdir -p /opt/soc-lab
if ($LASTEXITCODE -ne 0) { throw 'Kali container not ready.' }
foreach ($name in @('dvwa_cli.py', 'bounded_http_load.py', 'vt_lab_artifact.py', 'dvwa_web_flood.py')) {
    docker cp (Join-Path $PSScriptRoot $name) ($Container + ':/opt/soc-lab/' + $name)
    if ($LASTEXITCODE -ne 0) { throw ('Copy failed: ' + $name) }
}
docker exec --user 0 $Container chmod 644 /opt/soc-lab/dvwa_cli.py /opt/soc-lab/bounded_http_load.py /opt/soc-lab/vt_lab_artifact.py /opt/soc-lab/dvwa_web_flood.py
if ($LASTEXITCODE -ne 0) { throw 'Kali helper permissions not set.' }
Write-Output 'Helpers ready. Open docker exec -it kali-attacker bash. No session ID input is required.'
