param(
    [string]$GoRoot = "",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$GoBridgeDir = Join-Path $RepoRoot "wgbridge-go"
$DesktopDir = Join-Path $RepoRoot "desktop-win"
$DistDir = Join-Path $RepoRoot "dist"

if ([string]::IsNullOrWhiteSpace($GoRoot)) {
    $cmdGo = Get-Command go -ErrorAction SilentlyContinue
    if ($cmdGo) {
        $GoRoot = Split-Path -Parent (Split-Path -Parent $cmdGo.Source)
    } else {
        $candidates = @(
            (Join-Path $env:LOCALAPPDATA "Programs\Go"),
            "C:\Program Files\Go",
            "C:\Go"
        )
        foreach ($cand in $candidates) {
            if (Test-Path (Join-Path $cand "bin\go.exe")) {
                $GoRoot = $cand
                break
            }
        }
    }
}

if ([string]::IsNullOrWhiteSpace($GoRoot) -or -not (Test-Path (Join-Path $GoRoot "bin\go.exe"))) {
    throw "Go toolchain not found. Install Go or pass -GoRoot explicitly."
}

$goPathBin = Join-Path $env:USERPROFILE "go\bin"
$pathList = @((Join-Path $GoRoot "bin"), $goPathBin)
if (Test-Path "C:\msys64\ucrt64\bin\gcc.exe") {
    $pathList += "C:\msys64\ucrt64\bin"
}
$env:PATH = ($pathList -join ";") + ";" + $env:PATH

$wailsCmd = Get-Command wails -ErrorAction SilentlyContinue
if (-not $wailsCmd) {
    Write-Host "Installing Wails v2 CLI..."
    & go install github.com/wailsapp/wails/v2/cmd/wails@latest
    if ($LASTEXITCODE -ne 0) { throw "Failed to install Wails v2 CLI" }
}

$hasGcc = [bool](Get-Command gcc -ErrorAction SilentlyContinue)
$testArgs = @("test", "-v", "-count=1")
if ($hasGcc) {
    $env:CGO_ENABLED = "1"
    $testArgs += "-race"
}

if (-not $SkipTests) {
    Write-Host "[1/5] Verifying shared wgbridge-go engine..."
    Push-Location $GoBridgeDir
    try {
        & go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "wgbridge-go vet failed" }
        & go @testArgs ./...
        if ($LASTEXITCODE -ne 0) { throw "wgbridge-go tests failed" }

        $prevCgo = $env:CGO_ENABLED
        $env:CGO_ENABLED = "0"
        $env:GOOS = "android"
        $env:GOARCH = "arm64"
        & go build ./...
        if ($LASTEXITCODE -ne 0) { throw "Android arm64 compile check failed" }
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        if ($prevCgo) { $env:CGO_ENABLED = $prevCgo } else { Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue }
    } finally {
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Pop-Location
    }

    Write-Host "[2/5] Verifying desktop-win runtime..."
    Push-Location $DesktopDir
    try {
        & go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "desktop-win vet failed" }
        & go @testArgs ./...
        if ($LASTEXITCODE -ne 0) { throw "desktop-win tests failed" }
    } finally {
        Pop-Location
    }
}

Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host "[3/5] Building WireGuardPlus-Windows-x64.exe via Wails v2..."
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
$outExeName = "WireGuardPlus-Windows-x64.exe"
$distExe = Join-Path $DistDir $outExeName

$verifyExe = $distExe
$wasDistRunning = $false
Push-Location $DesktopDir
try {
    & wails build -clean -platform windows/amd64 -trimpath -ldflags "-s -w -buildid=" -o $outExeName
    if ($LASTEXITCODE -ne 0) { throw "wails build failed with exit code $LASTEXITCODE" }
    $builtExe = Join-Path $DesktopDir "build\bin\$outExeName"
    if (-not (Test-Path $builtExe)) {
        throw "Expected Wails output missing at $builtExe"
    }
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DistDir "WireGuardPlus-Windows-x64-new.exe"), ($distExe + ".old")
    $runningDist = @(Get-Process -Name "WireGuardPlus-Windows-x64" -ErrorAction SilentlyContinue | Where-Object { $_.Path -and ([string]::Equals([System.IO.Path]::GetFullPath($_.Path), [System.IO.Path]::GetFullPath($distExe), [System.StringComparison]::OrdinalIgnoreCase)) })
    if ($runningDist.Count -gt 0) {
        $wasDistRunning = $true
        $runningDist | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Milliseconds 350
    }
    try {
        Copy-Item -Force $builtExe $distExe
    } catch [System.IO.IOException] {
        $oldSidecar = $distExe + ".old"
        Remove-Item -Force -ErrorAction SilentlyContinue $oldSidecar
        if (Test-Path $distExe) {
            Move-Item -Force $distExe $oldSidecar
        }
        Copy-Item -Force $builtExe $distExe
        Remove-Item -Force -ErrorAction SilentlyContinue $oldSidecar
    }
    $verifyExe = $distExe
} finally {
    Pop-Location
}

Write-Host "[4/5] Packaging WireGuardPlus-Windows-x64-Portable.zip..."
$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wgplus_portable_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
$distZip = Join-Path $DistDir "WireGuardPlus-Windows-x64-Portable.zip"
try {
    Copy-Item -Force $verifyExe (Join-Path $stageDir "WireGuardPlus.exe")
    [System.IO.File]::WriteAllText((Join-Path $stageDir "portable.flag"), "1`n", [System.Text.UTF8Encoding]::new($false))
    $readme = @(
        "WireGuard Plus for Windows - Portable Edition",
        "==============================================",
        "",
        "1. Keep 'portable.flag' beside WireGuardPlus.exe so all encrypted config data",
        "   and WebView2 state stay strictly inside ./wgplus-data/ (zero AppData writes).",
        "2. Requires zero Admin privileges, installs zero network drivers, and never",
        "   conflicts with Tailscale, corporate VPNs, or AdGuard.",
        "3. When moving your portable folder to a different PC, export a .wgplus",
        "   passphrase-encrypted backup from the UI (DPAPI keys are tied to the PC user).",
        ""
    ) -join "`r`n"
    [System.IO.File]::WriteAllText((Join-Path $stageDir "PORTABLE_README.txt"), $readme, [System.Text.UTF8Encoding]::new($false))
    if (Test-Path $distZip) { Remove-Item -Force $distZip }
    Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $distZip -CompressionLevel Optimal
} finally {
    Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
}

Write-Host "[5/5] Running headless --self-check smoke verification..."
$selfOutFile = Join-Path ([System.IO.Path]::GetTempPath()) ("wgplus_selfcheck_" + [Guid]::NewGuid().ToString("N") + ".json")
try {
    $proc = Start-Process -FilePath $verifyExe -ArgumentList "--self-check" -RedirectStandardOutput $selfOutFile -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "Built binary --self-check exited with code $($proc.ExitCode)"
    }
    $selfJson = Get-Content -Raw $selfOutFile
    $parsedSelf = $selfJson | ConvertFrom-Json
    if (-not $parsedSelf.ok) {
        throw "Built binary --self-check returned ok=false"
    }
    Write-Host $selfJson
} finally {
    Remove-Item -Force $selfOutFile -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Build artifacts ready:"
Get-Item $verifyExe, $distZip | ForEach-Object {
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host ("  {0} ({1} bytes) SHA-256: {2}" -f $_.Name, $_.Length, $hash)
}
if ($wasDistRunning) {
    Start-Process -FilePath $distExe -ArgumentList "--minimized"
    Write-Host "Restarted $outExeName in background tray after in-place replacement."
}
