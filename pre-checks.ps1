#Requires -Version 5.1
<#
.SYNOPSIS
    Verifies machine is correctly configured before an exam.

.DESCRIPTION
    AUTO CHECKS : Script definitively judges PASS / FAIL.
    OTHERS      : Script lists info, invigilator verifies visually.
    Run as Administrator for full results.

.EXAMPLE
    .\Exam-ReadinessCheck.ps1
#>

[CmdletBinding()]
param()

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-C {
    param([string]$T, [ConsoleColor]$C = "White")
    Write-Host $T -ForegroundColor $C
}

function Clear-LastLine {
    $top = [Console]::CursorTop - 1
    if ($top -lt 0) { $top = 0 }
    [Console]::SetCursorPosition(0, $top)
    Write-Host (" " * 72)
    [Console]::SetCursorPosition(0, $top)
}

$width     = 72
$line      = "─" * $width
$passCount = 0
$failCount = 0
$results   = [System.Collections.Generic.List[PSCustomObject]]::new()

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$timestamp = Get-Date -Format 'yyyy-MM-dd HH-mm-ss'
$logFile   = Join-Path $scriptDir "pre-checks $timestamp.log"
$transcriptStarted = $false
try {
    Start-Transcript -Path $logFile -Force | Out-Null
    $transcriptStarted = $true
} catch {}

function Add-Result {
    param(
        [string]$Check,
        [ValidateSet("PASS","FAIL")]
        [string]$Status,
        [string]$Detail = ""
    )
    $results.Add([PSCustomObject]@{ Check = $Check; Status = $Status; Detail = $Detail })
    if ($Status -eq "PASS") { $script:passCount++ } else { $script:failCount++ }

    $icon  = if ($Status -eq "PASS") { "v" } else { "X" }
    $color = if ($Status -eq "PASS") { "Green" } else { "Red" }
    Write-Host "  " -NoNewline
    Write-Host "[$icon]" -NoNewline -ForegroundColor $color
    Write-Host ("  {0,-44}" -f $Check) -NoNewline -ForegroundColor White
    Write-Host $Status -ForegroundColor $color
    if ($Detail) { Write-C "        └─ $Detail" DarkGray }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-C "  $Title" Cyan
    Write-C "  $line" DarkGray
    Write-Host ""
}

function Write-OtherHeader {
    param([string]$Title)
    Write-Host ""
    Write-C "    $Title" Yellow
}

function Write-OtherItem {
    param([string]$Text, [ConsoleColor]$C = "White")
    Write-Host "       - $Text" -ForegroundColor $C
}

function Invoke-WithTimeout {
    param([scriptblock]$ScriptBlock, [int]$TimeoutSeconds = 10, $FallbackValue = $null)
    $job = Start-Job -ScriptBlock $ScriptBlock
    if (Wait-Job $job -Timeout $TimeoutSeconds) {
        $r = Receive-Job $job
        Remove-Job $job -Force
        return $r
    }
    Remove-Job $job -Force
    return $FallbackValue
}

# ── Elevation check ───────────────────────────────────────────────────────────

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")

# ── Header ────────────────────────────────────────────────────────────────────

$hostname = try { [System.Net.Dns]::GetHostName() } catch { $env:COMPUTERNAME }

Write-Host ""
Write-C ("=" * $width) Cyan
Write-C "  Host: $hostname   |   $(Get-Date -f 'yyyy-MM-dd HH:mm')" Cyan
if (-not $isAdmin) {
    Write-C "  [!] Not running as Administrator -- some checks may be incomplete" Yellow
}
Write-C ("=" * $width) Cyan


# ══════════════════════════════════════════════════════════════════════════════
# PRE-LOAD
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-C "  Loading data, please wait..." DarkGray

Write-Host "  ... Reading network adapters" -ForegroundColor DarkGray
try   { $allAdapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop }
catch { $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue }
if (-not $allAdapters) { $allAdapters = @() }
Clear-LastLine

Write-Host "  ... Reading PnP devices (may take a moment)" -ForegroundColor DarkGray
$allPnp = Invoke-WithTimeout -TimeoutSeconds 30 -ScriptBlock {
    Get-PnpDevice -ErrorAction SilentlyContinue
} -FallbackValue @()
Clear-LastLine

Write-Host "  ... Reading TCP connections" -ForegroundColor DarkGray
$tcpListening = Invoke-WithTimeout -TimeoutSeconds 8 -ScriptBlock {
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalPort
} -FallbackValue $null
Clear-LastLine

Write-C "  Done. Running checks..." DarkGray
Start-Sleep -Milliseconds 200


# ══════════════════════════════════════════════════════════════════════════════
# AUTO CHECKS
# ══════════════════════════════════════════════════════════════════════════════

Write-Section "AUTO CHECKS"

# ── WiFi ──────────────────────────────────────────────────────────────────────
# HardwareInterface guards against virtual adapters.
# PhysicalMediaType is primary signal; InterfaceDescription is fallback
# for drivers that don't report PhysicalMediaType correctly.
$wifiAdapters = $allAdapters | Where-Object {
    $_.HardwareInterface -eq $true -and
    (
        $_.PhysicalMediaType -match "802\.11|Wireless" -or
        $_.InterfaceDescription -match "Wi-?Fi|Wireless|802\.11|WLAN"
    )
}
$activeWifi = $wifiAdapters | Where-Object { $_.Status -eq "Up" }

if ($activeWifi) {
    $names = ($activeWifi | Select-Object -ExpandProperty Name) -join ", "
    Add-Result "WiFi Disabled" "FAIL" "$names is active"
} elseif ($wifiAdapters) {
    $names = ($wifiAdapters | Select-Object -ExpandProperty Name) -join ", "
    Add-Result "WiFi Disabled" "PASS" "Found but disabled: $names"
} else {
    Add-Result "WiFi Disabled" "PASS" "Not detected (likely disabled at BIOS level)"
}

# ── Bluetooth ─────────────────────────────────────────────────────────────────
# Bluetooth does not appear in Get-NetAdapter when disabled/BIOS off.
# Get-PnpDevice -Class Bluetooth is the only reliable source.
# Status "OK" means active; disabled in Device Manager shows "Error" or absent.
$btPnp = $allPnp | Where-Object { $_.Class -eq "Bluetooth" -and $_.Status -eq "OK" }

if (-not $btPnp) {
    Add-Result "Bluetooth Disabled" "PASS" "Not detected (disabled or not present)"
} else {
    Add-Result "Bluetooth Disabled" "FAIL" "Bluetooth is active -- disable in Device Manager or BIOS"
}

# ── Ethernet ──────────────────────────────────────────────────────────────────
# HardwareInterface guards against virtual adapters (VirtualBox = False, Hyper-V = False).
# PhysicalMediaType "802.3" is primary; InterfaceDescription is fallback.
# notmatch guard prevents WiFi/BT accidentally matching via description fallback.
# Note: Ethernet only appears when cable is plugged in -- absent = not connected = FAIL.
$ethernetAdapters = $allAdapters | Where-Object {
    $_.HardwareInterface -eq $true -and
    (
        $_.PhysicalMediaType -match "802\.3" -or
        $_.InterfaceDescription -match "Ethernet|LAN|GbE|GigE|10GbE"
    ) -and
    $_.InterfaceDescription -notmatch "Wi-?Fi|Wireless|802\.11|WLAN|Bluetooth"
}
$activeEthernet = $ethernetAdapters | Where-Object { $_.Status -eq "Up" }

if ($activeEthernet) {
    $names = ($activeEthernet | Select-Object -ExpandProperty Name) -join ", "
    Add-Result "Ethernet LAN Active" "PASS" "Active: $names"
} else {
    Add-Result "Ethernet LAN Active" "FAIL" "No physical Ethernet active -- plug in LAN cable"
}

# ── USB Storage ───────────────────────────────────────────────────────────────
$usbStorage = $allPnp | Where-Object { $_.InstanceId -like "USBSTOR\*" -and $_.Status -eq "OK" }

if ($usbStorage) {
    $names = ($usbStorage | Select-Object -ExpandProperty FriendlyName) -join ", "
    Add-Result "No USB Storage Connected" "FAIL" "Found: $names"
} else {
    Add-Result "No USB Storage Connected" "PASS" "No USB storage detected"
}

# ── Single display ────────────────────────────────────────────────────────────
$monitors = @($allPnp | Where-Object { $_.Class -eq "Monitor" -and $_.Status -eq "OK" })

if ($monitors.Count -eq 1) {
    Add-Result "Single Display Only" "PASS" "$($monitors[0].FriendlyName)"
} elseif ($monitors.Count -eq 0) {
    Add-Result "Single Display Only" "PASS" "Could not detect via PnP (verify physically)"
} else {
    $names = ($monitors | Select-Object -ExpandProperty FriendlyName) -join ", "
    Add-Result "Single Display Only" "FAIL" "$($monitors.Count) displays detected: $names"
}

# ── RDP ───────────────────────────────────────────────────────────────────────
try {
    $rdp = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
           -Name "fDenyTSConnections" -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 1) {
        Add-Result "Remote Desktop Disabled" "PASS" "RDP is disabled"
    } else {
        Add-Result "Remote Desktop Disabled" "FAIL" "RDP is ENABLED -- disable via System Properties > Remote"
    }
} catch {
    Add-Result "Remote Desktop Disabled" "FAIL" "Could not read registry -- run as Administrator"
}

# ── Suspicious ports ──────────────────────────────────────────────────────────
$suspiciousPorts = @(
    @{ Port = 3389; Name = "RDP" },
    @{ Port = 5900; Name = "VNC" },
    @{ Port = 5800; Name = "VNC-HTTP" },
    @{ Port = 5938; Name = "TeamViewer" },
    @{ Port = 7070; Name = "AnyDesk" },
    @{ Port = 4444; Name = "Common RAT" },
    @{ Port = 6568; Name = "AnyDesk-alt" },
    @{ Port = 8443; Name = "Remote-alt" }
)

if ($null -ne $tcpListening) {
    $found = $suspiciousPorts | Where-Object { $_.Port -in $tcpListening }
    if ($found) {
        $detail = ($found | ForEach-Object { "$($_.Port) ($($_.Name))" }) -join ", "
        Add-Result "No Remote Access Ports Open" "FAIL" "Listening: $detail"
    } else {
        Add-Result "No Remote Access Ports Open" "PASS" "No suspicious ports open"
    }
} else {
    Add-Result "No Remote Access Ports Open" "FAIL" "Could not query ports -- run as Administrator"
}

# ── Guest account ─────────────────────────────────────────────────────────────
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
    if ($guest.Enabled) {
        Add-Result "Guest Account Disabled" "FAIL" "Guest account is enabled -- disable it"
    } else {
        Add-Result "Guest Account Disabled" "PASS" "Guest account is disabled"
    }
} catch {
    Add-Result "Guest Account Disabled" "PASS" "Guest account not found"
}

# ══════════════════════════════════════════════════════════════════════════════
# OTHERS  (invigilator reviews these manually)
# ══════════════════════════════════════════════════════════════════════════════

Write-Section "OTHERS"
Write-C "  Review the lists below and confirm nothing looks suspicious." DarkGray

# ── Active network adapters ───────────────────────────────────────────────────
Write-OtherHeader "Active Network Adapters:"
$activeAdapters = $allAdapters | Where-Object { $_.Status -eq "Up" } | Sort-Object Name
if ($activeAdapters) {
    foreach ($a in $activeAdapters) {
        $hw = if ($a.HardwareInterface) { "physical" } else { "virtual" }
        Write-OtherItem "$($a.Name)  [$($a.InterfaceDescription)]  ($hw)"
    }
} else {
    Write-C "       (none)" DarkGray
}

# ── Audio devices ─────────────────────────────────────────────────────────────
Write-OtherHeader "Audio Devices:"
$audioDevices = $allPnp | Where-Object {
    $_.Class -in @("AudioEndpoint","Media")
} | Sort-Object Status, FriendlyName
if ($audioDevices) {
    foreach ($d in $audioDevices) {
        $status    = if ($d.Status) { $d.Status } else { "Unknown" }
        $lineColor = if ($status -eq "OK") { "White" } else { "DarkGray" }
        Write-OtherItem "$($d.FriendlyName)  [$status]" $lineColor
    }
} else {
    Write-C "       (none detected)" DarkGray
}

# ── Connected USB devices ─────────────────────────────────────────────────────
Write-OtherHeader "Connected USB Devices:"
$usbDevices = $allPnp | Where-Object {
    $_.InstanceId -like "USB\VID*" -and $_.Status -eq "OK"
} | Sort-Object FriendlyName
if ($usbDevices) {
    foreach ($d in $usbDevices) {
        $cls = if ($d.Class) { "  [$($d.Class)]" } else { "" }
        Write-OtherItem "$($d.FriendlyName)$cls"
    }
} else {
    Write-C "       (none detected)" DarkGray
}

# ── Input devices ─────────────────────────────────────────────────────────────
Write-OtherHeader "Input Devices (Mouse / Keyboard / Touchpad):"
$hidDevices = $allPnp | Where-Object {
    $_.Class -eq "HIDClass" -and $_.Status -eq "OK"
} | Sort-Object FriendlyName
if ($hidDevices) {
    foreach ($d in $hidDevices) { Write-OtherItem $d.FriendlyName }
} else {
    Write-C "       (none detected)" DarkGray
}

# ── Display adapters ──────────────────────────────────────────────────────────
Write-OtherHeader "Display Adapters:"
$gpus = $allPnp | Where-Object {
    $_.Class -eq "Display"
} | Sort-Object Status, FriendlyName
if ($gpus) {
    foreach ($d in $gpus) {
        $status    = if ($d.Status) { $d.Status } else { "Unknown" }
        $lineColor = if ($status -eq "OK") { "White" } else { "DarkGray" }
        Write-OtherItem "$($d.FriendlyName)  [$status]" $lineColor
    }
} else {
    Write-C "       (none detected)" DarkGray
}

# ── Local users ───────────────────────────────────────────────────────────────
Write-OtherHeader "Local Users:"
$localUsers = Get-LocalUser -ErrorAction SilentlyContinue
if ($localUsers) {
    foreach ($u in $localUsers | Sort-Object Name) {
        $status    = if ($u.Enabled) { "Enabled" } else { "Disabled" }
        $lineColor = if ($u.Enabled) { "White" } else { "DarkGray" }
        Write-OtherItem "$($u.Name)  [$status]" $lineColor
    }
} else {
    Write-C "       (could not enumerate users)" DarkGray
}


# ══════════════════════════════════════════════════════════════════════════════
# VERDICT
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ""

if ($failCount -eq 0) {
    Write-C ("=" * $width) Green
    Write-Host ""
    Write-Host "  Checks: $($results.Count)   " -NoNewline
    Write-Host "Passed: $passCount  " -NoNewline -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Green
    Write-Host ""
    Write-C "    [v]  AUTO CHECKS PASSED" Green
    Write-C "         Review the OTHERS section above before starting the exam." Green
    Write-Host ""
    Write-C ("=" * $width) Green
} else {
    Write-C ("=" * $width) Red
    Write-Host ""
    Write-Host "  Checks: $($results.Count)   " -NoNewline
    Write-Host "Passed: $passCount   " -NoNewline -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host ""
    Write-C "    [X]  NOT READY  --  $failCount check(s) failed" Red
    Write-Host ""
    Write-C ("=" * $width) Red
    Write-Host ""
    Write-C "  Fix before proceeding:" Yellow
    foreach ($r in ($results | Where-Object { $_.Status -eq "FAIL" })) {
        Write-C "    - $($r.Check): $($r.Detail)" Yellow
    }
}

Write-Host ""

if (-not $isAdmin) {
    Write-C "  NOTE: Run as Administrator for complete results." DarkGray
    Write-C "  Right-click PowerShell > Run as Administrator, then re-run." DarkGray
    Write-Host ""
}

if ($transcriptStarted) {
    try {
        Stop-Transcript | Out-Null
        Write-C "  Log saved: $logFile" DarkGray
        Write-Host ""
    } catch {}
}