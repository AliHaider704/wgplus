param(
    [string]$GoRoot = "",
    [string]$GoPath = "",
    [string]$GoCache = "",
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$AndroidHome = $env:ANDROID_HOME,
    [string]$AndroidNdkHome = $env:ANDROID_NDK_HOME
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$GoModuleDir = Join-Path $RepoRoot "wgbridge-go"
$OutputAar = Join-Path $RepoRoot "app\libs\wgbridge.aar"
$OutputSourcesJar = Join-Path $RepoRoot "app\libs\wgbridge-sources.jar"

if ([string]::IsNullOrWhiteSpace($GoRoot)) {
    $cmdGo = Get-Command go -ErrorAction SilentlyContinue
    if ($cmdGo) {
        $GoRoot = Split-Path -Parent (Split-Path -Parent $cmdGo.Source)
    } else {
        throw "Go toolchain not found on PATH. Install Go or pass -GoRoot explicitly."
    }
}

$env:GOROOT = $GoRoot
if (-not [string]::IsNullOrWhiteSpace($GoPath)) { $env:GOPATH = $GoPath }
if (-not [string]::IsNullOrWhiteSpace($GoCache)) { $env:GOCACHE = $GoCache }
$env:JAVA_HOME = $JavaHome
$env:ANDROID_HOME = $AndroidHome
$env:ANDROID_SDK_ROOT = $AndroidHome
$env:ANDROID_NDK_HOME = $AndroidNdkHome

$pathParts = @("$GoRoot\bin", "$JavaHome\bin")
if (-not [string]::IsNullOrWhiteSpace($env:GOPATH)) {
    $pathParts += "$($env:GOPATH)\bin"
}
$env:PATH = ($pathParts -join ";") + ";" + $env:PATH

Write-Host "[1/4] Running Go unit tests (TCP CONNECT + UDP ASSOCIATE + UAPI Stats)..."
Push-Location $GoModuleDir
try {
    & go test -v ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed with exit code $LASTEXITCODE" }

    Write-Host "[2/4] Building wgbridge.aar for arm64-v8a and armeabi-v7a (minSdk 21)..."
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $OutputAar) | Out-Null
    & gomobile bind "-target=android/arm64,android/arm" -androidapi 21 -o $OutputAar .
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

Write-Host "[3/4] Applying LSPatch InMemoryDexClassLoader guard to go/Seq.class..."
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wgbridge_patch_" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
try {
    $aarUnpack = Join-Path $workDir "aar"
    $srcUnpack = Join-Path $workDir "src"
    $clsUnpack = Join-Path $workDir "cls"
    New-Item -ItemType Directory -Force -Path $aarUnpack, $srcUnpack, $clsUnpack | Out-Null

    $jarExe = Join-Path $JavaHome "bin\jar.exe"
    $javacExe = Join-Path $JavaHome "bin\javac.exe"
    $javapExe = Join-Path $JavaHome "bin\javap.exe"
    $androidJar = Join-Path $AndroidHome "platforms\android-35\android.jar"

    Push-Location $aarUnpack
    & $jarExe xf $OutputAar
    Pop-Location

    Push-Location $srcUnpack
    & $jarExe xf $OutputSourcesJar
    Pop-Location

    $seqJavaPath = Join-Path $srcUnpack "go\Seq.java"
    $seqSource = Get-Content -Raw $seqJavaPath
    $needle = 'System.loadLibrary("gojni");'
    $replacement = 'try { System.loadLibrary("gojni"); } catch (UnsatisfiedLinkError ignored) { /* Preloaded via System.load in NativeBridgeLoader under LSPatch */ }'
    if (-not $seqSource.Contains($needle)) {
        throw "Expected System.loadLibrary(""gojni"") not found in generated go/Seq.java"
    }
    $patchedSeqSource = $seqSource.Replace($needle, $replacement)
    [System.IO.File]::WriteAllText($seqJavaPath, $patchedSeqSource, [System.Text.UTF8Encoding]::new($false))

    Push-Location $clsUnpack
    & $jarExe xf (Join-Path $aarUnpack "classes.jar")
    Pop-Location

    & $javacExe -source 8 -target 8 -bootclasspath $androidJar -cp $clsUnpack -d $clsUnpack $seqJavaPath
    if ($LASTEXITCODE -ne 0) { throw "javac compilation of patched go/Seq.java failed" }

    $newClassesJar = Join-Path $aarUnpack "classes.jar"
    Remove-Item -Force $newClassesJar
    & $jarExe cf $newClassesJar -C $clsUnpack .
    if ($LASTEXITCODE -ne 0) { throw "Repacking classes.jar failed" }

    Push-Location $srcUnpack
    Remove-Item -Force $OutputSourcesJar
    & $jarExe cf $OutputSourcesJar .
    Pop-Location

    Remove-Item -Force $OutputAar
    & $jarExe cf $OutputAar -C $aarUnpack .
    if ($LASTEXITCODE -ne 0) { throw "Repacking wgbridge.aar failed" }

    Write-Host "[4/4] Verifying exported Wgbridge methods and go.Seq static initializer..."
    & $javapExe -cp $newClassesJar wgbridge.Wgbridge
    $seqDisasm = & $javapExe -c -cp $newClassesJar go.Seq
    if (-not ($seqDisasm -join "`n").Contains("java/lang/UnsatisfiedLinkError")) {
        throw "Verification failed: UnsatisfiedLinkError catch table missing in go.Seq.<clinit>"
    }
    Write-Host "SUCCESS: wgbridge.aar built and verified at $OutputAar"
} finally {
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}
