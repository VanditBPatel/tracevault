<#
.SYNOPSIS
    TraceVault Windows evidence collector.

.DESCRIPTION
    Exports Windows event logs (Security, System and Sysmon by default) from THIS machine into
    JSON Lines files that TraceVault reads, and writes a manifest.json with the SHA-256 of every
    file, so the chain of custody starts at collection time.

    The script only reads event logs and writes into -OutDir. It changes no settings, installs
    nothing and sends nothing over the network. Copy the output folder to the analyst machine and
    run:  tracevault ingest-collection <CASE-ID> <folder>

    Run it from an elevated PowerShell: the Security log needs Administrator rights. Works on
    Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Since
    Start of the time window (default: 72 hours ago).

.PARAMETER Until
    End of the time window (default: now).

.PARAMETER OutDir
    Output folder (default: .\TraceVault-<COMPUTERNAME>-<UTC timestamp>). Must not already contain files.

.PARAMETER Channels
    Event log channels to export.

.PARAMETER Examiner
    Name of the person collecting (recorded in the manifest).

.PARAMETER MaxEvents
    Optional cap per channel (newest first) for very busy hosts. 0 = no cap.

.PARAMETER IncludeEvtx
    Also export each channel as a native .evtx file (wevtutil epl) for preservation.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Collect-TraceVault.ps1 -Examiner "J. Doe"

.EXAMPLE
    .\Collect-TraceVault.ps1 -Since (Get-Date).AddDays(-7) -IncludeEvtx -OutDir E:\IR\WS01
#>
[CmdletBinding()]
param(
    [datetime]$Since = (Get-Date).AddHours(-72),
    [datetime]$Until = (Get-Date),
    [string]$OutDir,
    [string[]]$Channels = @('Security', 'System', 'Microsoft-Windows-Sysmon/Operational'),
    [string]$Examiner = $env:USERNAME,
    [int]$MaxEvents = 0,
    [switch]$IncludeEvtx
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$CollectorVersion = '0.4.1'
$EventNs = 'http://schemas.microsoft.com/win/2004/08/events/event'

function ConvertTo-UtcIso([datetime]$Value) {
    # Six fractional digits: Python 3.10's datetime.fromisoformat rejects seven.
    return $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function Get-ChannelSlug([string]$Channel) {
    switch -Regex ($Channel) {
        '^Microsoft-Windows-Sysmon/' { return 'sysmon' }
        default { return ($Channel.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-') }
    }
}

# Performance matters: a busy server logs hundreds of thousands of events. Events are read with
# EventLogReader (Get-WinEvent renders every message, ~30x slower), fields are pulled from the
# event XML with one regex, and JSON is written directly instead of via ConvertTo-Json.
$DataRe = New-Object System.Text.RegularExpressions.Regex(
    "<Data Name='([^']*)'>([^<]*)</Data>|<Data Name='([^']*)'\s*/>|<Data>([^<]*)</Data>", 'Compiled')
$CtrlRe = New-Object System.Text.RegularExpressions.Regex('[\x00-\x1f]', 'Compiled')
# Most values need no JSON escaping; testing for that inline avoids a function call per field.
$NeedsEscapeRe = New-Object System.Text.RegularExpressions.Regex('[\\"\x00-\x1f]', 'Compiled')
$IsoFormat = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
$Invariant = [Globalization.CultureInfo]::InvariantCulture
$Sb = New-Object System.Text.StringBuilder 4096

function ConvertTo-JsonString([string]$Value) {
    if ($null -eq $Value) { return 'null' }
    $v = $Value.Replace('\', '\\').Replace('"', '\"')
    if ($CtrlRe.IsMatch($v)) {
        $v = $CtrlRe.Replace($v, { param($m) '\u{0:x4}' -f [int][char]$m.Value })
    }
    return '"' + $v + '"'
}

function ConvertTo-JsonLine($EventRecord) {
    # One event -> one flat JSON object in the same shape as Winlogbeat/OTRF exports: system
    # fields plus every EventData value under its own name (TargetUserName, CommandLine, ...).
    $xmlText = $EventRecord.ToXml()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    [void]$Sb.Clear()
    [void]$Sb.Append('{"EventID":').Append([int]$EventRecord.Id)
    [void]$Sb.Append(',"TimeCreated":"').Append($EventRecord.TimeCreated.ToUniversalTime().ToString($IsoFormat, $Invariant)).Append('"')
    [void]$Sb.Append(',"Channel":').Append((ConvertTo-JsonString $EventRecord.LogName))
    [void]$Sb.Append(',"Computer":').Append((ConvertTo-JsonString $EventRecord.MachineName))
    [void]$Sb.Append(',"ProviderName":').Append((ConvertTo-JsonString $EventRecord.ProviderName))
    [void]$Sb.Append(',"RecordId":').Append($(if ($null -ne $EventRecord.RecordId) { $EventRecord.RecordId } else { 'null' }))
    [void]$Sb.Append(',"Level":').Append($(if ($null -ne $EventRecord.Level) { $EventRecord.Level } else { 'null' }))
    foreach ($n in 'EventID', 'TimeCreated', 'Channel', 'Computer', 'ProviderName', 'RecordId', 'Level') { [void]$seen.Add($n) }

    $i = 0
    foreach ($m in $DataRe.Matches($xmlText)) {
        $i++
        if ($m.Groups[1].Success) { $name = $m.Groups[1].Value; $value = $m.Groups[2].Value }
        elseif ($m.Groups[3].Success) { $name = $m.Groups[3].Value; $value = '' }
        else { $name = "param$i"; $value = $m.Groups[4].Value }
        if (-not $seen.Add($name)) { continue }
        # Match XML parsers: literal CR LF in text becomes LF (an encoded &#xD; stays a CR), and
        # text that is only whitespace counts as empty.
        if ($value.IndexOf("`r") -ge 0) { $value = $value.Replace("`r`n", "`n").Replace("`r", "`n") }
        if ($value.Length -gt 0 -and $value.Trim().Length -eq 0) { $value = '' }
        if ($value.IndexOf('&') -ge 0) { $value = [System.Net.WebUtility]::HtmlDecode($value) }
        [void]$Sb.Append(',')
        if ($NeedsEscapeRe.IsMatch($name)) { [void]$Sb.Append((ConvertTo-JsonString $name)) } else { [void]$Sb.Append('"').Append($name).Append('"') }
        [void]$Sb.Append(':')
        if ($NeedsEscapeRe.IsMatch($value)) { [void]$Sb.Append((ConvertTo-JsonString $value)) } else { [void]$Sb.Append('"').Append($value).Append('"') }
    }
    # Some events (e.g. 1102 "audit log cleared") keep their fields under UserData instead.
    if ($xmlText.IndexOf('<UserData>') -ge 0) {
        $xml = [xml]$xmlText
        $nsm = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $nsm.AddNamespace('e', $EventNs)
        foreach ($node in $xml.SelectNodes('/e:Event/e:UserData/*/*', $nsm)) {
            if ($seen.Add($node.LocalName)) {
                [void]$Sb.Append(',').Append((ConvertTo-JsonString $node.LocalName)).Append(':').Append((ConvertTo-JsonString $node.InnerText))
            }
        }
    }
    [void]$Sb.Append('}')
    return $Sb.ToString()
}

function Test-Elevated {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------- setup

$startedAt = Get-Date
$hostName = $env:COMPUTERNAME
if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) ("TraceVault-{0}-{1}" -f $hostName, $startedAt.ToUniversalTime().ToString('yyyyMMddTHHmmssZ'))
}
if (Test-Path -LiteralPath $OutDir) {
    if (Get-ChildItem -LiteralPath $OutDir -Force | Select-Object -First 1) {
        throw "Output folder '$OutDir' is not empty. Use a new folder so the collection is unambiguous."
    }
} else {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path
$elevated = Test-Elevated
if (-not $elevated) {
    Write-Warning 'Not running as Administrator: the Security log will be skipped. Re-run from an elevated PowerShell.'
}

Write-Host "TraceVault collector $CollectorVersion on $hostName"
Write-Host ("Window: {0} -> {1} (UTC)" -f (ConvertTo-UtcIso $Since), (ConvertTo-UtcIso $Until))
Write-Host "Output: $OutDir"

$utf8 = New-Object System.Text.UTF8Encoding($false)
$files = New-Object System.Collections.ArrayList
$skipped = New-Object System.Collections.ArrayList

# ---------------------------------------------------------------------------- export

foreach ($channel in $Channels) {
    $slug = Get-ChannelSlug $channel
    try {
        $null = Get-WinEvent -ListLog $channel -ErrorAction Stop
    } catch {
        [void]$skipped.Add([ordered]@{ channel = $channel; reason = "log not present on this host ($($_.Exception.Message.Trim()))" })
        Write-Host "  - $channel : not present, skipped"
        continue
    }

    $path = Join-Path $OutDir ("{0}_{1}.jsonl" -f $hostName, $slug)
    $writer = New-Object System.IO.StreamWriter($path, $false, $utf8)
    $count = 0
    $note = $null
    $reader = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $xpath = "*[System[TimeCreated[@SystemTime>='{0}' and @SystemTime<='{1}']]]" -f `
            $Since.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $Invariant),
            $Until.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", $Invariant)
        $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
            $channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath)
        # With a cap, read newest first so the most recent activity is kept.
        $query.ReverseDirection = ($MaxEvents -gt 0)
        $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
        while ($null -ne ($evt = $reader.ReadEvent())) {
            try { $writer.WriteLine((ConvertTo-JsonLine $evt)) } finally { $evt.Dispose() }
            $count++
            if ($count % 5000 -eq 0) {
                Write-Host ("    {0} : {1} events ({2:N0}/s)..." -f $channel, $count, ($count / [math]::Max(0.001, $timer.Elapsed.TotalSeconds)))
            }
            if ($MaxEvents -gt 0 -and $count -ge $MaxEvents) { break }
        }
        if ($count -eq 0) { $note = 'no events in the time window' }
    } catch [System.UnauthorizedAccessException] {
        $writer.Close(); Remove-Item -LiteralPath $path
        [void]$skipped.Add([ordered]@{ channel = $channel; reason = 'access denied - run as Administrator' })
        Write-Host "  - $channel : access denied, skipped"
        continue
    } catch {
        $writer.Close()
        throw "Failed while exporting $channel after $count events: $($_.Exception.Message)"
    } finally {
        $writer.Close()
        if ($reader) { $reader.Dispose() }
    }

    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    $entry = [ordered]@{
        name = (Split-Path -Leaf $path); channel = $channel; format = 'jsonl'; events = $count
        bytes = (Get-Item -LiteralPath $path).Length; sha256 = $hash
    }
    if ($note) { $entry['note'] = $note }
    if ($MaxEvents -gt 0 -and $count -ge $MaxEvents) { $entry['note'] = "capped at $MaxEvents newest events" }
    [void]$files.Add($entry)
    Write-Host ("  + {0} : {1} events in {2:N1}s -> {3}" -f $channel, $count, $timer.Elapsed.TotalSeconds, $entry.name)

    if ($IncludeEvtx) {
        $evtx = Join-Path $OutDir ("{0}_{1}.evtx" -f $hostName, $slug)
        $startMs = [long]([datetime]::UtcNow - $Since.ToUniversalTime()).TotalMilliseconds
        $endMs = [long][math]::Max(0, ([datetime]::UtcNow - $Until.ToUniversalTime()).TotalMilliseconds)
        $xpath = "*[System[TimeCreated[timediff(@SystemTime) <= $startMs and timediff(@SystemTime) >= $endMs]]]"
        & wevtutil.exe epl $channel $evtx "/q:$xpath"
        if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $evtx)) {
            [void]$files.Add([ordered]@{
                name = (Split-Path -Leaf $evtx); channel = $channel; format = 'evtx'; events = $null
                bytes = (Get-Item -LiteralPath $evtx).Length
                sha256 = (Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash.ToLowerInvariant()
            })
            Write-Host "    also preserved native $((Split-Path -Leaf $evtx))"
        } else {
            [void]$skipped.Add([ordered]@{ channel = $channel; reason = "native .evtx export failed (wevtutil exit $LASTEXITCODE)" })
        }
    }
}

# ---------------------------------------------------------------------------- manifest

$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
$manifest = [ordered]@{
    collector             = 'TraceVault Windows collector'
    version               = $CollectorVersion
    host                  = $hostName
    domain                = $env:USERDOMAIN
    os                    = $(if ($os) { "$($os.Caption) $($os.Version)" } else { [Environment]::OSVersion.VersionString })
    powershell            = $PSVersionTable.PSVersion.ToString()
    elevated              = $elevated
    examiner              = $Examiner
    collected_by_account  = "$env:USERDOMAIN\$env:USERNAME"
    window                = [ordered]@{ since = (ConvertTo-UtcIso $Since); until = (ConvertTo-UtcIso $Until) }
    started_at            = ConvertTo-UtcIso $startedAt
    finished_at           = ConvertTo-UtcIso (Get-Date)
    host_utc_offset_minutes = [int][TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
    files                 = @($files)
    skipped               = @($skipped)
}
$manifestPath = Join-Path $OutDir 'manifest.json'
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 5), $utf8)
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

Write-Host ''
Write-Host "Done. $($files.Count) file(s), $($skipped.Count) skipped."
Write-Host "manifest.json SHA-256: $manifestHash"
Write-Host '  Record this hash in your notes; TraceVault logs it again at ingest.'
Write-Host "Next, on the analyst machine:  tracevault ingest-collection <CASE-ID> `"$OutDir`""
