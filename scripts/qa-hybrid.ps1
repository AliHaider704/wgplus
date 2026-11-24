param(
    [string[]]$WirelessTargets = @(),
    [string]$AdbPath = "",
    [switch]$SkipBuild,
    [switch]$SkipInstall,
    [switch]$SkipWindows,
    [switch]$SkipAndroid
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $RepoRoot "dist"
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-QaRow {
    param([string]$Target, [string]$Env, [string]$Status, [string]$Details)
    $Results.Add([PSCustomObject]@{
        Target      = $Target
        Environment = $Env
        Status      = $Status
        Details     = $Details
    })
}

function Resolve-AdbExe {
    param([string]$Explicit)
    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($Explicit)) { $candidates += $Explicit }
    $cmd = Get-Command adb -ErrorAction SilentlyContinue
    if ($cmd) { $candidates += $cmd.Source }
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Android\Sdk\platform-tools\adb.exe")
    }
    $candidates += "C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe"
    $candidates += "C:\Users\Ali\Downloads\Compressed\rootAVD-master\rootAVD-master\adb.exe"
    foreach ($c in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path $c)) {
            return $c
        }
    }
    return ""
}

function Find-LatestUniversalApk {
    if (-not (Test-Path $DistDir)) { return $null }
    return Get-ChildItem -Path $DistDir -Filter "WireGuardPlus-*.apk" |
        Where-Object { $_.Name -notmatch "-(arm64-v8a|armeabi-v7a|x86_64)\.apk$" } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Parse-ContentCallJson {
    param([string]$RawOutput)
    if ([string]::IsNullOrWhiteSpace($RawOutput)) { return $null }
    $startIdx = $RawOutput.IndexOf("json={")
    if ($startIdx -lt 0) { return $null }
    $jsonStart = $startIdx + 5
    $endIdx = $RawOutput.LastIndexOf("}]")
    if ($endIdx -le $jsonStart) { return $null }
    $jsonText = $RawOutput.Substring($jsonStart, $endIdx - $jsonStart)
    try {
        return ($jsonText | ConvertFrom-Json)
    } catch {
        return $null
    }
}

Write-Host "=== WireGuard Plus Hybrid QA Orchestrator ===" -ForegroundColor Cyan

# 0. Optional full local build
if (-not $SkipBuild) {
    Write-Host "[Build] Running Go tests & Windows desktop build..."
    Push-Location (Join-Path $RepoRoot "wgbridge-go")
    try {
        & go test ./...
        if ($LASTEXITCODE -ne 0) { throw "wgbridge-go tests failed" }
    } finally { Pop-Location }

    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $RepoRoot "scripts\build-windows.ps1")
    if ($LASTEXITCODE -ne 0) { throw "build-windows.ps1 failed" }

    Write-Host "[Build] Running Android unit tests + release APK build..."
    $appBuildDir = Join-Path $RepoRoot "app\build"
    if (Test-Path $appBuildDir) {
        cmd /c "rmdir /s /q `"$appBuildDir`""
    }
    Push-Location $RepoRoot
    try {
        & (Join-Path $RepoRoot "gradlew.bat") testDebugUnitTest assembleRelease --no-daemon --max-workers=1 --no-watch-fs
        if ($LASTEXITCODE -ne 0) { throw "Gradle build failed" }
    } finally { Pop-Location }
}

# 1. Static APK / ELF / 16KB Audit
$universalApk = Find-LatestUniversalApk
if ($null -eq $universalApk) {
    Add-QaRow -Target "APK Audit" -Env "Static" -Status "FAIL" -Details "No WireGuardPlus-*.apk found in dist\"
} else {
    $verPrefix = $universalApk.BaseName
    $auditTargets = [System.Collections.Generic.List[string]]::new()
    $auditTargets.Add($universalApk.FullName)
    foreach ($abiSuffix in @("arm64-v8a", "armeabi-v7a")) {
        $splitFile = Join-Path $DistDir "$verPrefix-$abiSuffix.apk"
        if (Test-Path $splitFile) { $auditTargets.Add($splitFile) }
    }
    $pyCmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pyCmd) { $pyCmd = Get-Command python3 -ErrorAction SilentlyContinue }
    if (-not $pyCmd) {
        Add-QaRow -Target $universalApk.Name -Env "Static ELF/16KB" -Status "WARN" -Details "Python not found on PATH; skipped ELF audit"
    } else {
        $auditScript = Join-Path $PSScriptRoot "audit-android-apk.py"
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $auditOut = & $pyCmd.Source $auditScript @auditTargets 2>&1
        $auditExit = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        $summaryLine = ($auditOut | Select-String "Audit Summary:" | Select-Object -Last 1).ToString()
        $warnsMatch = [regex]::Match($summaryLine, "warnings=(\d+)")
        $warnCnt = if ($warnsMatch.Success) { [int]$warnsMatch.Groups[1].Value } else { 0 }
        $st = if ($auditExit -ne 0) { "FAIL" } elseif ($warnCnt -gt 0) { "WARN" } else { "PASS" }
        Add-QaRow -Target $universalApk.Name -Env "Static ELF/16KB" -Status $st -Details "$summaryLine (audited $($auditTargets.Count) APKs)"
    }
}

# 2. Windows Local Check
if (-not $SkipWindows) {
    $winExe = Join-Path $DistDir "WireGuardPlus-Windows-x64.exe"
    if (-not (Test-Path $winExe)) {
        Add-QaRow -Target "Windows Desktop" -Env "windows/amd64" -Status "FAIL" -Details "Missing $winExe"
    } else {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $scRaw = (& $winExe --self-check 2>$null | Out-String)
        $scExit = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        $scJson = $null
        try { $scJson = $scRaw | ConvertFrom-Json } catch {}
        if ($scExit -ne 0 -or $null -eq $scJson -or -not $scJson.ok) {
            Add-QaRow -Target "Windows Desktop" -Env "windows/amd64" -Status "FAIL" -Details "--self-check failed (exit=$scExit)"
        } else {
            $wintun = Get-NetAdapter -Name "WireGuardPlusCalls" -ErrorAction SilentlyContinue
            $wintunState = if ($wintun) { "Wintun=$($wintun.Status)" } else { "Wintun=Inactive(NoAdmin)" }
            $rejects = if ($scJson.statsPreview) { $scJson.statsPreview.socksAuthRejectCount } else { 0 }
            $details = "ok=true port=$($scJson.socksPort) clients=$($scJson.clientsDetected) profiles=$($scJson.profilesCount) authReject=$rejects $wintunState"
            Add-QaRow -Target "Windows Desktop" -Env "windows/amd64" -Status "PASS" -Details $details
        }
    }
}

# 3. Android USB + Wireless Fleet Check
if (-not $SkipAndroid) {
    $adb = Resolve-AdbExe -Explicit $AdbPath
    if ([string]::IsNullOrWhiteSpace($adb)) {
        Add-QaRow -Target "Android Fleet" -Env "ADB" -Status "WARN" -Details "adb.exe not found; pass -AdbPath or install platform-tools"
    } else {
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        foreach ($wt in $WirelessTargets) {
            if (-not [string]::IsNullOrWhiteSpace($wt)) {
                & $adb connect $wt 2>&1 | Out-Null
            }
        }
        $devLines = & $adb devices 2>$null
        $ErrorActionPreference = $prevPref

        $onlineSerials = [System.Collections.Generic.List[string]]::new()
        foreach ($line in $devLines) {
            if ($line -match "^(\S+)\s+device\s*$") {
                $onlineSerials.Add($Matches[1])
            } elseif ($line -match "^(\S+)\s+(unauthorized|offline)\s*$") {
                Add-QaRow -Target $Matches[1] -Env "ADB ($($Matches[2]))" -Status "WARN" -Details "Device $($Matches[2]); approve USB debugging prompt"
            }
        }

        if ($onlineSerials.Count -eq 0) {
            Add-QaRow -Target "Android Fleet" -Env "ADB" -Status "WARN" -Details "No online ADB devices detected"
        }

        foreach ($serial in $onlineSerials) {
            $prevPref = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $mfg = ((& $adb -s $serial shell getprop ro.product.manufacturer 2>$null | Out-String).Trim())
            $model = ((& $adb -s $serial shell getprop ro.product.model 2>$null | Out-String).Trim())
            $rel = ((& $adb -s $serial shell getprop ro.build.version.release 2>$null | Out-String).Trim())
            $sdk = ((& $adb -s $serial shell getprop ro.build.version.sdk 2>$null | Out-String).Trim())
            $abi = ((& $adb -s $serial shell getprop ro.product.cpu.abi 2>$null | Out-String).Trim())
            $idOut = ((& $adb -s $serial shell "su -c id 2>/dev/null || true" 2>$null | Out-String).Trim())
            $ErrorActionPreference = $prevPref

            $isRoot = $idOut -match "uid=0"
            $privTag = if ($isRoot) { "Root" } else { "Non-Root" }
            $envLabel = "Android $rel (API $sdk) $abi [$privTag]"
            $devLabel = "$mfg $model ($serial)"

            if (-not $SkipInstall -and $null -ne $universalApk) {
                $prevPref = $ErrorActionPreference
                $ErrorActionPreference = "Continue"
                $instOut = (& $adb -s $serial install -r -d $universalApk.FullName 2>&1 | Out-String)
                $instExit = $LASTEXITCODE
                $ErrorActionPreference = $prevPref
                if ($instExit -ne 0) {
                    Add-QaRow -Target $devLabel -Env $envLabel -Status "FAIL" -Details "APK install failed: $($instOut.Trim())"
                    continue
                }
            }

            $prevPref = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            $statusRaw = (& $adb -s $serial shell content call --uri content://org.telegram.wgplus.module.status --method automation_status 2>$null | Out-String)
            $logTail = (& $adb -s $serial logcat -d -t 500 2>$null | Out-String)
            $ErrorActionPreference = $prevPref

            $stJson = Parse-ContentCallJson -RawOutput $statusRaw
            $fatalHits = ([regex]::Matches($logTail, "FATAL EXCEPTION.*[\r\n]+.*org\.telegram\.wgplus")).Count
            $jniErrHits = ([regex]::Matches($logTail, "UnsatisfiedLinkError.*gojni")).Count
            $authRejectHits = ([regex]::Matches($logTail, "SOCKS_AUTH/REJECT")).Count
            $hopStormHits = ([regex]::Matches($logTail, "ENSURE_HOP|peer reset hopPort=true")).Count

            if ($null -eq $stJson) {
                Add-QaRow -Target $devLabel -Env $envLabel -Status "WARN" -Details "automation_status unavailable (module not installed or stopped); fatal=$fatalHits jniErr=$jniErrHits"
                continue
            }

            $ver = if ($stJson.version) { $stJson.version } else { "?" }
            $running = [bool]$stJson.tunnelRunning
            $hsHealthy = [bool]$stJson.handshakeHealthy
            $hsSec = [int64]$stJson.lastHandshakeSec
            $hookPkg = if ($stJson.hookPackage) { $stJson.hookPackage } else { "none" }
            $privMode = if ($stJson.privilegeMode) { $stJson.privilegeMode } else { "STANDARD" }

            $rowStatus = "PASS"
            if ($fatalHits -gt 0 -or $jniErrHits -gt 0 -or $authRejectHits -gt 0) {
                $rowStatus = "FAIL"
            } elseif ($running -and -not $hsHealthy) {
                $rowStatus = "WARN"
            } elseif ($hopStormHits -gt 10) {
                $rowStatus = "WARN"
            } elseif (-not $running) {
                $rowStatus = "WARN"
            }

            $det = "v$ver run=$running hsHealthy=$hsHealthy hsSec=$hsSec mode=$privMode hook=$hookPkg authRej=$authRejectHits hopBurst=$hopStormHits fatal=$fatalHits"
            Add-QaRow -Target $devLabel -Env $envLabel -Status $rowStatus -Details $det
        }
    }
}

Write-Host "`n=== QA Summary Matrix ===" -ForegroundColor Cyan
$Results | Format-Table -AutoSize -Wrap

$failCount = @($Results | Where-Object { $_.Status -eq "FAIL" }).Count
if ($failCount -gt 0) {
    exit 1
}
exit 0
