# Prints the SHA-256 of release APKs and Windows artifacts, and verifies any offline Ed25519 signature.
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $RepoRoot "dist"

$targets = @()
$targets += Get-ChildItem $DistDir -Filter *.apk -ErrorAction SilentlyContinue | Sort-Object Name
$targets += Get-ChildItem $DistDir -Filter "WireGuardPlus-Windows-x64*" -ErrorAction SilentlyContinue | Sort-Object Name

foreach ($item in $targets) {
    "{0}  {1}" -f (Get-FileHash $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $item.Name
}

$sumsPath = Join-Path $DistDir "SHA256SUMS-windows.txt"
$sumsSigPath = Join-Path $DistDir "SHA256SUMS-windows.txt.sig"
if ((Test-Path $sumsPath) -and (Test-Path $sumsSigPath)) {
    $pubs = @()
    $primaryPub = Join-Path $RepoRoot ".offline_keys\updater_ed25519_primary.pub"
    $backupPub = Join-Path $RepoRoot ".offline_keys\updater_ed25519_backup.pub"
    if (Test-Path $primaryPub) { $pubs += (Get-Content -Raw $primaryPub).Trim() }
    if (Test-Path $backupPub) { $pubs += (Get-Content -Raw $backupPub).Trim() }
    $signTool = Join-Path $RepoRoot "scripts\sign-windows-sums.go"
    if (($pubs.Count -gt 0) -and (Test-Path $signTool)) {
        $goExe = (Get-Command go -ErrorAction SilentlyContinue).Source
        if (-not $goExe) {
            $candidate = Join-Path $env:LOCALAPPDATA "Programs\Go\bin\go.exe"
            if (Test-Path $candidate) { $goExe = $candidate }
        }
        if ($goExe) {
            & $goExe run $signTool -verify -pub ($pubs -join ",") -in $sumsPath -sig $sumsSigPath
            if ($LASTEXITCODE -ne 0) { throw "Ed25519 signature verification failed for $sumsSigPath" }
        } else {
            Write-Warning "Go toolchain not found; skipped Ed25519 signature verification."
        }
    }
}
