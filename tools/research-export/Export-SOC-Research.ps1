# Requires Windows PowerShell 5.1 or PowerShell 7, and Docker CLI access.
# Read-only collection from existing containers. No services are restarted.
[CmdletBinding()]
param(
    [string[]]$ContainerNames = @(),
    [string]$ProjectPath = '',
    [string]$AIPath = '',
    [string]$ModelPath = '',
    [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$script:SecretWord = '(?i)(password|passwd|\bpwd\b|secret|token|api[_-]?key|private[_-]?key|credential|authorization|cookie|access[_-]?key|connection[_-]?string|chpasswd)'
$script:AuthArgument = '(?i)(?:^|\s|["''])(?:-u(?:\s|=)|--user(?:\s|=)|--proxy-user\b|--password\b|--token\b|--header\b|-H(?:\s|$)|-p[^\s,\]"'']+)'
$script:SecretFile = '(?i)(^\.env(?:\.|$)|client\.keys|authd\.pass|internal_users|keystore|credentials?|passwords?|cookies?|secrets?|tokens?|api[_-]?keys?|(?:^|[._-])id_(?:rsa|ed25519|ecdsa)(?:\.|$))'
$script:Notes = New-Object 'System.Collections.Generic.List[string]'
$script:Exported = New-Object 'System.Collections.Generic.List[object]'
$script:HostBytes = 0L
$script:HostFiles = 0
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)

function Protect-Text([string]$Text) {
    if ($null -eq $Text) { return '' }
    $s = $Text -replace '(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED PRIVATE KEY]'
    $tag = '(?:password|passwd|pass|secret|token|api_key|apikey|private_key|key|authorization|cookie)'
    $s = [regex]::Replace($s, "(?is)<(?<tag>$tag)(?:\s[^>]*)?>.*?</\k<tag>\s*>", '<${tag}>[REDACTED]</${tag}>')
    $s = $s -replace '(?i)([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@', '$1[REDACTED]@'
    $s = $s -replace '(?i)\b(?:gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,})\b', '[REDACTED TOKEN]'
    $s = $s -replace '(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/_.=\-]+', '$1 [REDACTED]'
    $s = $s -replace '\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', '[REDACTED JWT]'
    $jsonSecret = '(?i)("[^"\r\n]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|authorization|cookie|credential|connection[_-]?string)[^"\r\n]*"\s*:\s*)"(?:[^"\\]|\\.)*"'
    $s = $s -replace $jsonSecret, '$1"[REDACTED]"'
    $result = New-Object 'System.Collections.Generic.List[string]'
    $blockedIndent = -1
    $tripleQuote = ''
    foreach ($line in ($s -split '\r?\n')) {
        $indent = $line.Length - $line.TrimStart().Length
        if ($tripleQuote) {
            $result.Add('# [REDACTED multiline credential]')
            if ($line.Contains($tripleQuote)) { $tripleQuote = '' }
            continue
        }
        if ($blockedIndent -ge 0 -and $line.Trim() -and $indent -gt $blockedIndent) {
            $result.Add((' ' * $indent) + '# [REDACTED credential block]')
            continue
        }
        if ($line.Trim()) { $blockedIndent = -1 }
        $suspicious = (($line -match $script:SecretWord) -and
            ($line -match '[:=]|chpasswd|(?i)--?(?:password|passwd|token|api-key)\b')) -or
            ($line -match $script:AuthArgument)
        if ($suspicious -and $line -notmatch '\[REDACTED') {
            $result.Add((' ' * $indent) + '# [REDACTED sensitive setting or command]')
            $blockedIndent = $indent
            foreach ($delimiter in @('"""', "'''")) {
                if (([regex]::Matches($line, [regex]::Escape($delimiter))).Count % 2 -eq 1) {
                    $tripleQuote = $delimiter
                }
            }
        } else { $result.Add($line) }
    }
    return ($result -join "`n")
}

function Write-Text([string]$Path, [string]$Text) {
    $parent = Split-Path -Parent $Path
    [void][IO.Directory]::CreateDirectory($parent)
    [IO.File]::WriteAllText($Path, $Text, $script:Utf8)
}

function Write-SafeText([string]$Path, [string]$Text) {
    Write-Text $Path (Protect-Text $Text)
}

function ConvertTo-SafeObject($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Protect-Text $Value) }
    if ($Value -is [Collections.IDictionary] -or $Value -is [pscustomobject]) {
        $clean = [ordered]@{}
        if ($Value -is [Collections.IDictionary]) { $keys = @($Value.Keys) }
        else { $keys = @($Value.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($key in $keys) {
            if ($key -match $script:SecretWord) { $clean[$key] = '[REDACTED]' }
            else {
                if ($Value -is [Collections.IDictionary]) { $entryValue = $Value[$key] }
                else { $entryValue = $Value.PSObject.Properties[$key].Value }
                $clean[$key] = ConvertTo-SafeObject $entryValue
            }
        }
        return $clean
    }
    if ($Value -is [Collections.IEnumerable]) {
        $array = New-Object 'System.Collections.Generic.List[object]'
        foreach ($entry in $Value) { $array.Add((ConvertTo-SafeObject $entry)) }
        return ,$array.ToArray()
    }
    return $Value
}

function Write-SafeJson([string]$Path, $Value) {
    $safe = ConvertTo-SafeObject $Value
    Write-Text $Path ($safe | ConvertTo-Json -Depth 40)
}

function Quote-NativeArgument([string]$Value) {
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-ReadOnlyDocker([string[]]$DockerArgs, [string]$InputText = '') {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:DockerExe
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = $script:Utf8
    $psi.StandardErrorEncoding = $script:Utf8
    if ($null -ne $psi.PSObject.Properties['ArgumentList']) {
        foreach ($arg in $DockerArgs) { $psi.ArgumentList.Add($arg) }
    } else {
        $psi.Arguments = (($DockerArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    try {
        [void]$p.Start()
        $stdoutTask = $p.StandardOutput.ReadToEndAsync()
        $stderrTask = $p.StandardError.ReadToEndAsync()
        if ($InputText) { $p.StandardInput.Write($InputText.Replace("`r`n", "`n")) }
        $p.StandardInput.Close()
        $timedOut = -not $p.WaitForExit(60000)
        if ($timedOut) { $p.Kill(); $p.WaitForExit() }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        $exitCode = $p.ExitCode
        if ($timedOut) { $exitCode = 124; $stderr += "`nDocker client exceeded 60 seconds." }
        return [pscustomobject]@{
            Command = 'docker ' + (($DockerArgs | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
            ExitCode = $exitCode; Stdout = $stdout; Stderr = $stderr; TimedOut = $timedOut
        }
    } finally { $p.Dispose() }
}

function Save-CommandReport([string]$Path, $Result) {
    $safeStdout = Protect-Text $Result.Stdout
    $safeStderr = Protect-Text $Result.Stderr
    $body = "COMMAND: $($Result.Command)`nEXIT CODE: $($Result.ExitCode)`nTIMED OUT: $($Result.TimedOut)`n`nSTDOUT:`n$safeStdout`n`nSTDERR:`n$safeStderr"
    Write-Text $Path $body
    if ($Result.ExitCode -ne 0) { $script:Notes.Add("Command failed ($($Result.ExitCode)): $($Result.Command)") }
}

function Get-SafeCommand($Items) {
    $values = @($Items | Where-Object { $null -ne $_ })
    $joined = $values -join ' '
    if ($joined -match $script:SecretWord -or $joined -match '://[^/\s]+@' -or $joined -match $script:AuthArgument) {
        return '[REDACTED: command may contain credentials]'
    }
    return $values
}

function Export-HostFile([string]$Source, [string]$Destination) {
    try {
        $item = Get-Item -LiteralPath $Source -Force
        if ($item.Name -match $script:SecretFile -or $item.Extension -match '^\.(?:key|pem|pfx|p12|crt)$') {
            $script:Notes.Add("Skipped sensitive filename: $Source"); return
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $script:Notes.Add("Skipped symlink/reparse point: $Source"); return
        }
        if ($item.Length -gt 1048576) { $script:Notes.Add("Skipped file over 1 MiB: $Source"); return }
        if ($script:HostFiles -ge 300 -or $script:HostBytes + $item.Length -gt 20971520) {
            $script:Notes.Add("Host export limit reached; skipped: $Source"); return
        }
        $text = [IO.File]::ReadAllText($item.FullName)
        if ($text.IndexOf([char]0) -ge 0) { $script:Notes.Add("Skipped binary file: $Source"); return }
        if ($item.Extension -eq '.json') {
            try { $parsed = ConvertFrom-Json -InputObject $text; Write-SafeJson $Destination $parsed }
            catch { Write-SafeText $Destination $text; $script:Notes.Add("JSON could not be parsed; text redaction used: $Source") }
        } else { Write-SafeText $Destination $text }
        $script:HostFiles++
        $script:HostBytes += $item.Length
        $script:Exported.Add([pscustomobject]@{
            Source = $item.FullName; Export = $Destination.Substring($script:ExportRoot.Length + 1)
            SourceBytes = $item.Length; Note = 'Sanitized inspection copy; not a restore backup.'
        })
    } catch { $script:Notes.Add("Cannot export ${Source}: $($_.Exception.Message)") }
}

function Export-TextTree([string]$Root, [string]$Kind) {
    if (-not $Root) { return }
    try {
        $rootItem = Get-Item -LiteralPath $Root -Force
        if (-not $rootItem.PSIsContainer -or $rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            $script:Notes.Add("Not a regular directory; skipped $Kind path: $Root"); return
        }
        $base = $rootItem.FullName.TrimEnd([char[]]@('\', '/'))
        if ($base -eq [IO.Path]::GetPathRoot($rootItem.FullName).TrimEnd([char[]]@('\', '/'))) {
            $script:Notes.Add("Refusing to scan an entire filesystem; choose a project directory: $Root"); return
        }
    }
    catch { $script:Notes.Add("$Kind directory unavailable: $Root"); return }
    $queue = New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($base)
    $excluded = '^(?:\..*|venv.*|env|__pycache__|node_modules|datasets?|raw|logs?|live|runs?|checkpoints?|models?|prepared.*|dist|build|vendor|cache|backups?|SOC-Research-.*|secrets?|certs?|certificates?)$'
    $visited = 0
    while ($queue.Count -gt 0) {
        if ($visited -ge 1500) { $script:Notes.Add("Directory limit reached for $Kind"); break }
        $directory = $queue.Dequeue(); $visited++
        try { $items = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) }
        catch { $script:Notes.Add("Cannot list directory: $directory"); continue }
        foreach ($item in $items) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                $script:Notes.Add("Skipped symlink/reparse point: $($item.FullName)"); continue
            }
            if ($item.PSIsContainer) {
                if ($item.Name -notmatch $excluded -and $item.FullName -ne $script:ExportRoot) { $queue.Enqueue($item.FullName) }
                continue
            }
            if ($item.Name -match $script:SecretFile) { continue }
            $accept = $false
            if ($Kind -eq 'model-metadata') {
                $accept = $item.Name -match '^(?:model|features|preprocessor|metrics|golden|golden-predictions|status|config)\.json$|^requirements.*\.txt$'
            } else {
                $accept = $item.Extension -match '^\.(?:py|ps1|cmd|bat|sh|json|toml|ya?ml|conf|ini|cfg|rules|xml|lock|js|jsx|ts|tsx|css|html|md)$' -or
                    $item.Name -match '^Dockerfile(?:\..*)?$|^requirements.*\.txt$|^\.dockerignore$'
            }
            if (-not $accept) { continue }
            $relative = $item.FullName.Substring($base.Length).TrimStart([char[]]@('\', '/'))
            Export-HostFile $item.FullName (Join-Path (Join-Path $script:ExportRoot $Kind) $relative)
        }
    }
}

$snapshotScript = @'
#!/bin/sh
# This collector reads configuration and status only. No application script is run.
section() { printf '\n===== %s =====\n' "$1"; }
run() {
    section "COMMAND: $*"
    "$@"
    code=$?
    printf '\nCOMMAND_EXIT=%s\n' "$code"
}
run uname -a
run id
run ps -eo pid,ppid,comm
if command -v ip >/dev/null 2>&1; then run ip -brief address; run ip route; fi
if command -v ss >/dev/null 2>&1; then run ss -lntu; fi
if command -v dpkg-query >/dev/null 2>&1; then
    run dpkg-query -W '-f=${Package}\t${Version}\n'
fi
if command -v suricata >/dev/null 2>&1; then run suricata --build-info; fi
if command -v pgrep >/dev/null 2>&1; then
    for pid in $(pgrep -x suricata 2>/dev/null); do
        section "SURICATA COMMAND LINE PID $pid"
        if [ -r "/proc/$pid/cmdline" ]; then tr '\000' ' ' < "/proc/$pid/cmdline"; printf '\n'; fi
    done
fi
if [ -x /var/ossec/bin/wazuh-control ]; then run /var/ossec/bin/wazuh-control status; fi
if [ -x /var/ossec/bin/agent_control ]; then run /var/ossec/bin/agent_control -lc; fi
if command -v journalctl >/dev/null 2>&1; then run journalctl --no-pager -n 0; fi
section 'LOG/JOURNAL PATH METADATA ONLY; NO LOG CONTENTS'
ls -ld /run/log/journal /var/log/journal /var/log/auth.log /var/log/suricata /var/ossec/logs/alerts /var/log/apache2 2>&1
list_files() {
    for f in \
        /etc/os-release /etc/ssh/sshd_config /etc/sudoers \
        /etc/rsyslog.conf /etc/systemd/journald.conf \
        /etc/audit/auditd.conf /etc/suricata/suricata.yaml \
        /etc/suricata/classification.config /etc/suricata/reference.config \
        /var/ossec/etc/ossec.conf /var/ossec/etc/internal_options.conf \
        /var/ossec/etc/local_internal_options.conf \
        /var/ossec/api/configuration/api.yaml \
        /etc/filebeat/filebeat.yml \
        /usr/share/wazuh-indexer/opensearch.yml \
        /usr/share/wazuh-indexer/config/opensearch.yml \
        /usr/share/wazuh-dashboard/config/opensearch_dashboards.yml \
        /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml \
        /root/.bashrc /root/.profile \
        /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh \
        /usr/local/sbin/start-soc-web.sh \
        /app/requirements.txt /app/pyproject.toml \
        /app/live-config.json /app/correlation-config.json
    do
        if [ -e "$f" ] || [ -L "$f" ]; then printf '%s\n' "$f"; fi
    done
    for d in /etc/ssh/sshd_config.d /etc/rsyslog.d /etc/systemd/journald.conf.d /etc/suricata \
        /var/lib/suricata/rules /var/ossec/etc/rules /var/ossec/etc/decoders \
        /var/ossec/etc/shared /etc/audit/rules.d /etc/sudoers.d \
        /etc/apache2/sites-enabled /etc/apache2/sites-available /etc/apache2/conf-available
    do
        if [ -d "$d" ]; then
            find "$d" -maxdepth 2 -type f \( -name '*.conf' -o -name '*.yaml' -o \
                -name '*.yml' -o -name '*.rules' -o -name '*.xml' -o -name '*.config' \) -print
        fi
    done
    if [ -d /etc/sudoers.d ]; then find /etc/sudoers.d -maxdepth 1 -type f ! -name '.*' -print; fi
}
section 'CONFIG INVENTORY'
list_files | LC_ALL=C sort -u
list_files | LC_ALL=C sort -u | (
    count=0
    total=0
    while IFS= read -r f; do
        section "FILE: $f"
        case "$f" in
            *client.keys*|*authd.pass*|*internal_users*|*cookie*|*.key|*.pem|*.p12|*.pfx)
                printf 'SKIPPED_SENSITIVE_FILENAME\n'; continue ;;
        esac
        if [ -L "$f" ]; then printf 'SKIPPED_SYMLINK\n'; continue; fi
        if [ ! -r "$f" ]; then printf 'SKIPPED_UNREADABLE\n'; continue; fi
        size=$(wc -c < "$f") || { printf 'SKIPPED_SIZE_ERROR\n'; continue; }
        printf 'SOURCE_BYTES=%s\n' "$size"
        if [ "$size" -gt 524288 ]; then
            printf 'SKIPPED_OVER_512_KIB; request this ruleset separately if needed\n'
            if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; fi
            continue
        fi
        if [ "$count" -ge 120 ] || [ $((total + size)) -gt 8388608 ]; then
            printf 'SKIPPED_CONTAINER_EXPORT_LIMIT\n'; continue
        fi
        count=$((count + 1)); total=$((total + size))
        cat "$f"
        code=$?
        printf '\nFILE_READ_EXIT=%s\n' "$code"
    done
    section "CONFIG_EXPORT_SUMMARY files=$count bytes=$total"
)
section 'COLLECTION_FINISHED'
'@

$dockerCommand = Get-Command docker -CommandType Application -ErrorAction Stop | Select-Object -First 1
$script:DockerExe = $dockerCommand.Source
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'SOC-Research-Exports' }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 6)
$script:ExportRoot = Join-Path $OutputDirectory ('SOC-Research-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $suffix)
[void][IO.Directory]::CreateDirectory($script:ExportRoot)
Write-Host "Collecting read-only inspection files into: $script:ExportRoot"

Save-CommandReport (Join-Path $script:ExportRoot 'docker-version.txt') (Invoke-ReadOnlyDocker @('version'))
Save-CommandReport (Join-Path $script:ExportRoot 'compose-version.txt') (Invoke-ReadOnlyDocker @('compose', 'version'))
$listing = Invoke-ReadOnlyDocker @('ps', '-a', '--format', '{{.Names}}|{{.Image}}|{{.Status}}')
Save-CommandReport (Join-Path $script:ExportRoot 'container-list.txt') $listing
if ($listing.ExitCode -ne 0) {
    $script:Notes.Add('Docker container listing failed. See stderr; no containers could be inspected.')
}
$selected = @($ContainerNames | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
if ($selected.Count -eq 0 -and $listing.ExitCode -eq 0) {
    $selected = @($listing.Stdout -split '\r?\n' | Where-Object {
        $_ -match '(?i)(ubuntu|endpoint|suricata|wazuh|kali|filebeat|logstash|(^|[-_./:|])soc([-_./:|]|$)|(^|[-_./:|])ai([-_./:|]|$))'
    } | ForEach-Object { ($_ -split '\|', 3)[0] } | Select-Object -Unique)
}
if ($selected.Count -eq 0) {
    $script:Notes.Add('No matching containers. Use -ContainerNames with the actual names shown in container-list.txt.')
}
$networkNames = New-Object 'System.Collections.Generic.HashSet[string]'
$composePaths = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($name in $selected) {
    Write-Host "Inspecting: $name"
    $safeName = $name -replace '[^A-Za-z0-9_.-]', '_'
    $dest = Join-Path $script:ExportRoot ('containers/' + $safeName)
    $inspect = Invoke-ReadOnlyDocker @('inspect', '--type', 'container', $name)
    if ($inspect.ExitCode -ne 0) { Save-CommandReport (Join-Path $dest 'inspect-error.txt') $inspect; continue }
    try { $c = @($inspect.Stdout | ConvertFrom-Json)[0] }
    catch { $script:Notes.Add("Invalid Docker inspect response for $name"); continue }
    $labels = $c.Config.Labels
    $compose = [ordered]@{}
    foreach ($label in @('com.docker.compose.project', 'com.docker.compose.service', 'com.docker.compose.version', 'com.docker.compose.project.working_dir', 'com.docker.compose.project.config_files')) {
        if ($labels -and $labels.PSObject.Properties[$label]) { $compose[$label] = $labels.$label }
    }
    $configLabel = $compose['com.docker.compose.project.config_files']
    if ($configLabel) { foreach ($path in ($configLabel -split ',')) { [void]$composePaths.Add($path.Trim()) } }
    $networks = @()
    if ($c.NetworkSettings.Networks) {
        foreach ($property in $c.NetworkSettings.Networks.PSObject.Properties) {
            [void]$networkNames.Add($property.Name)
            $networks += [ordered]@{ Name = $property.Name; IPAddress = $property.Value.IPAddress; Gateway = $property.Value.Gateway; Aliases = $property.Value.Aliases }
        }
    }
    $metadata = [ordered]@{
        Name = $c.Name; ImageReference = $c.Config.Image; ImageId = $c.Image
        Status = $c.State.Status; Running = $c.State.Running; ExitCode = $c.State.ExitCode; Health = $c.State.Health.Status
        User = $c.Config.User; WorkingDir = $c.Config.WorkingDir
        Entrypoint = @(Get-SafeCommand $c.Config.Entrypoint); Cmd = @(Get-SafeCommand $c.Config.Cmd)
        Healthcheck = @(Get-SafeCommand $c.Config.Healthcheck.Test)
        EnvironmentVariableNames = @($c.Config.Env | ForEach-Object { ($_ -split '=', 2)[0] })
        Mounts = @($c.Mounts | Select-Object Type, Name, Source, Destination, RW, Propagation)
        PublishedPorts = $c.NetworkSettings.Ports; Networks = $networks
        Privileged = $c.HostConfig.Privileged; CapAdd = $c.HostConfig.CapAdd; CapDrop = $c.HostConfig.CapDrop
        ReadonlyRootfs = $c.HostConfig.ReadonlyRootfs; NetworkMode = $c.HostConfig.NetworkMode
        PidMode = $c.HostConfig.PidMode; SecurityOpt = $c.HostConfig.SecurityOpt
        Memory = $c.HostConfig.Memory; NanoCpus = $c.HostConfig.NanoCpus; RestartPolicy = $c.HostConfig.RestartPolicy
        ComposeLabels = $compose
    }
    Write-SafeJson (Join-Path $dest 'docker-metadata.json') $metadata
    if ($c.State.Running) {
        $snapshot = Invoke-ReadOnlyDocker @('exec', '--user', '0', '-i', $name, 'sh', '-s') $snapshotScript
        Save-CommandReport (Join-Path $dest 'config-and-status.txt') $snapshot
        if ($snapshot.Stdout -match 'SKIPPED_|COMMAND_EXIT=[1-9]|FILE_READ_EXIT=[1-9]') {
            $script:Notes.Add("Some files/commands were skipped or failed in ${name}; see config-and-status.txt.")
        }
    } else {
        $script:Notes.Add("Container $name is stopped. Metadata only; it was not started.")
    }
}
foreach ($network in $networkNames) {
    $r = Invoke-ReadOnlyDocker @('network', 'inspect', $network)
    $safeName = $network -replace '[^A-Za-z0-9_.-]', '_'
    if ($r.ExitCode -ne 0) { Save-CommandReport (Join-Path $script:ExportRoot "networks/$safeName-error.txt") $r; continue }
    try {
        $n = @($r.Stdout | ConvertFrom-Json)[0]
        $safe = [ordered]@{ Name = $n.Name; Driver = $n.Driver; Internal = $n.Internal; EnableIPv6 = $n.EnableIPv6; IPAM = $n.IPAM.Config }
        Write-SafeJson (Join-Path $script:ExportRoot "networks/$safeName.json") $safe
    } catch { $script:Notes.Add("Invalid network response: $network") }
}
$composeNumber = 0
foreach ($path in $composePaths) {
    if ([IO.Path]::GetExtension($path) -notmatch '^\.(?:ya?ml|json)$') {
        $script:Notes.Add("Skipped non-YAML/JSON Compose label path: $path")
    } elseif (Test-Path -LiteralPath $path -PathType Leaf) {
        $composeNumber++
        Export-HostFile $path (Join-Path $script:ExportRoot ("compose/compose-$composeNumber-" + [IO.Path]::GetFileName($path)))
    } else { $script:Notes.Add("Compose file from label is not accessible on this host: $path. Supply -ProjectPath if available.") }
}
Export-TextTree $ProjectPath 'project-files'
Export-TextTree $AIPath 'ai-source'
Export-TextTree $ModelPath 'model-metadata'
if (-not $AIPath) { $script:Notes.Add('AIPath was not supplied. AI source was not exported.') }
if (-not $ProjectPath) { $script:Notes.Add('ProjectPath was not supplied. Only label-discovered Compose files and container configs were exported.') }

$readme = @'
SOC RESEARCH INSPECTION EXPORT

Read-only collection: no container was started/stopped/restarted and no service configuration was changed.
Docker inspect was filtered; environment VARIABLE NAMES are included, not their values.
No .env, client.keys, authd.pass, private key files, raw logs, datasets, venvs or model weights are intentionally collected.
Config text and source copies use best-effort credential redaction. Manually review before sharing.
Redacted copies are for inspection, not runnable source or a restore backup.

Read collection-summary.json and COLLECTION-NOTES.txt first. Missing files are not evidence that a service is absent.
Stopped containers have metadata only. Containers without sh or readable configs may have partial exports.
config-and-status.txt preserves command exit codes and stderr; inspect inner COMMAND_EXIT / FILE_READ_EXIT too.
Container exports cap individual files at 512 KiB and content at 120 files / 8 MiB per container.
Host files cap at 1 MiB each, 300 files / 20 MiB overall. Symlinks/reparse points are skipped.
Large Suricata rulesets are listed and hashed, not copied in full. Request them separately if needed.
AI source needs -AIPath; selected model JSON metadata needs -ModelPath. No model predictions are run.
Compose files are copied as text with redaction; docker compose config is deliberately not run because it interpolates secrets.
Local source paths, internal IP addresses, usernames and software versions may remain. Review them before sharing publicly.
This archive does not prove service readiness, detector accuracy or end-to-end AI-to-Wazuh delivery.
'@
Write-SafeText (Join-Path $script:ExportRoot 'README-FIRST.txt') $readme
Write-SafeText (Join-Path $script:ExportRoot 'COLLECTION-NOTES.txt') ($script:Notes -join "`n")
$summary = [ordered]@{
    CreatedAt = (Get-Date).ToUniversalTime().ToString('o')
    PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    SelectedContainers = $selected; HostFilesExported = $script:HostFiles; HostSourceBytes = $script:HostBytes
    NoteCount = $script:Notes.Count; Notes = @($script:Notes.ToArray()); ExportedHostFiles = @($script:Exported.ToArray())
    Scope = 'Read-only, sanitized configuration/source inspection; not a full lab backup or readiness test.'
}
Write-SafeJson (Join-Path $script:ExportRoot 'collection-summary.json') $summary
$hashLines = @(Get-ChildItem -LiteralPath $script:ExportRoot -Recurse -File | Sort-Object FullName | ForEach-Object {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $relative = $_.FullName.Substring($script:ExportRoot.Length + 1).Replace('\', '/')
    "$hash  $relative"
})
[IO.File]::WriteAllLines((Join-Path $script:ExportRoot 'SHA256SUMS.txt'), [string[]]$hashLines, $script:Utf8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = $script:ExportRoot + '.zip'
[IO.Compression.ZipFile]::CreateFromDirectory($script:ExportRoot, $zip)
Write-Host ''
Write-Host "DONE: $zip"
Write-Host "Collection notes: $($script:Notes.Count). Review COLLECTION-NOTES.txt and the exported files before sharing."
Write-Host 'No services were restarted. Upload the reviewed ZIP for analysis.'
