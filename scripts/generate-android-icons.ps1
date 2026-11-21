param(
    [string]$SourceIcon = "",
    [string]$ResDir = ""
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($SourceIcon)) {
    $SourceIcon = Join-Path $RepoRoot "desktop-win\build\appicon.png"
}
if ([string]::IsNullOrWhiteSpace($ResDir)) {
    $ResDir = Join-Path $RepoRoot "app\src\main\res"
}
if (-not (Test-Path $SourceIcon)) {
    throw "Source icon not found: $SourceIcon"
}

Add-Type -AssemblyName System.Drawing

$srcBmp = [System.Drawing.Bitmap]::FromFile((Resolve-Path $SourceIcon))
try {
    # Sample solid background color from inside the rounded square corner
    $bgSample = $srcBmp.GetPixel([int]($srcBmp.Width * 0.14), [int]($srcBmp.Height * 0.14))
    $bgHex = "#{0:X2}{1:X2}{2:X2}" -f $bgSample.R, $bgSample.G, $bgSample.B
    Write-Host "Sampled background color from appicon.png: $bgHex"

    # Write adaptive background color drawable
    $drawableDir = Join-Path $ResDir "drawable"
    New-Item -ItemType Directory -Force -Path $drawableDir | Out-Null
    $bgXml = @"
<?xml version="1.0" encoding="utf-8"?>
<shape xmlns:android="http://schemas.android.com/apk/res/android"
    android:shape="rectangle">
    <solid android:color="$bgHex" />
</shape>
"@
    [System.IO.File]::WriteAllText((Join-Path $drawableDir "ic_launcher_background.xml"), $bgXml.TrimStart(), [System.Text.UTF8Encoding]::new($false))

    # Write adaptive icon XMLs (API 26+)
    $anydpiDir = Join-Path $ResDir "mipmap-anydpi-v26"
    New-Item -ItemType Directory -Force -Path $anydpiDir | Out-Null
    $adaptiveXml = @"
<?xml version="1.0" encoding="utf-8"?>
<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">
    <background android:drawable="@drawable/ic_launcher_background" />
    <foreground android:drawable="@mipmap/ic_launcher_foreground" />
</adaptive-icon>
"@
    [System.IO.File]::WriteAllText((Join-Path $anydpiDir "ic_launcher.xml"), $adaptiveXml.TrimStart(), [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $anydpiDir "ic_launcher_round.xml"), $adaptiveXml.TrimStart(), [System.Text.UTF8Encoding]::new($false))

    # Build clean foreground bitmap (transparent background, solid emblem colors with smooth edge ramp)
    $fgSrc = New-Object System.Drawing.Bitmap($srcBmp.Width, $srcBmp.Height, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    for ($y = 0; $y -lt $srcBmp.Height; $y++) {
        for ($x = 0; $x -lt $srcBmp.Width; $x++) {
            $px = $srcBmp.GetPixel($x, $y)
            if ($px.A -lt 8) {
                $fgSrc.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(0, 0, 0, 0))
                continue
            }
            $dr = [int]$px.R - [int]$bgSample.R
            $dg = [int]$px.G - [int]$bgSample.G
            $db = [int]$px.B - [int]$bgSample.B
            $dist = [Math]::Sqrt($dr * $dr + $dg * $dg + $db * $db)
            if ($dist -le 14.0) {
                $fgSrc.SetPixel($x, $y, [System.Drawing.Color]::FromArgb(0, 0, 0, 0))
            } elseif ($dist -lt 36.0) {
                $factor = ($dist - 14.0) / 22.0
                $newA = [int][Math]::Min(255, [Math]::Round($px.A * $factor))
                $fgSrc.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($newA, $px.R, $px.G, $px.B))
            } else {
                $fgSrc.SetPixel($x, $y, $px)
            }
        }
    }

    # Find tight bounding box of non-transparent emblem in $fgSrc so it centers nicely in safe zone
    $minX = $fgSrc.Width
    $minY = $fgSrc.Height
    $maxX = 0
    $maxY = 0
    for ($y = 0; $y -lt $fgSrc.Height; $y++) {
        for ($x = 0; $x -lt $fgSrc.Width; $x++) {
            if ($fgSrc.GetPixel($x, $y).A -gt 20) {
                if ($x -lt $minX) { $minX = $x }
                if ($y -lt $minY) { $minY = $y }
                if ($x -gt $maxX) { $maxX = $x }
                if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }
    $cropW = [Math]::Max(1, ($maxX - $minX + 1))
    $cropH = [Math]::Max(1, ($maxY - $minY + 1))
    $cropSide = [Math]::Max($cropW, $cropH)
    $cropRect = New-Object System.Drawing.Rectangle(
        [int]($minX - ($cropSide - $cropW) / 2),
        [int]($minY - ($cropSide - $cropH) / 2),
        $cropSide,
        $cropSide
    )

    $densities = @(
        @{ name = "mipmap-mdpi";    fg = 108; legacy = 48 },
        @{ name = "mipmap-hdpi";    fg = 162; legacy = 72 },
        @{ name = "mipmap-xhdpi";   fg = 216; legacy = 96 },
        @{ name = "mipmap-xxhdpi";  fg = 324; legacy = 144 },
        @{ name = "mipmap-xxxhdpi"; fg = 432; legacy = 192 }
    )

    foreach ($d in $densities) {
        $dir = Join-Path $ResDir $d.name
        New-Item -ItemType Directory -Force -Path $dir | Out-Null

        # 1. Adaptive foreground (emblem spans ~58% of 108dp canvas = comfortably inside 66/108 = 61.1% safe zone)
        $fgSize = $d.fg
        $fgBmp = New-Object System.Drawing.Bitmap($fgSize, $fgSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [System.Drawing.Graphics]::FromImage($fgBmp)
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $emblemTarget = [int][Math]::Round($fgSize * 0.54)
        $offset = [int][Math]::Round(($fgSize - $emblemTarget) / 2.0)
        $destRect = New-Object System.Drawing.Rectangle($offset, $offset, $emblemTarget, $emblemTarget)
        $g.DrawImage($fgSrc, $destRect, $cropRect, [System.Drawing.GraphicsUnit]::Pixel)
        $g.Dispose()
        $fgBmp.Save((Join-Path $dir "ic_launcher_foreground.png"), [System.Drawing.Imaging.ImageFormat]::Png)
        $fgBmp.Dispose()

        # 2. Legacy rounded-squircle launcher icon
        $legSize = $d.legacy
        $legBmp = New-Object System.Drawing.Bitmap($legSize, $legSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g2 = [System.Drawing.Graphics]::FromImage($legBmp)
        $g2.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g2.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g2.Clear([System.Drawing.Color]::Transparent)
        $g2.DrawImage($srcBmp, 0, 0, $legSize, $legSize)
        $g2.Dispose()
        $legBmp.Save((Join-Path $dir "ic_launcher.png"), [System.Drawing.Imaging.ImageFormat]::Png)

        # 3. Legacy round launcher icon
        $rndBmp = New-Object System.Drawing.Bitmap($legSize, $legSize, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g3 = [System.Drawing.Graphics]::FromImage($rndBmp)
        $g3.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g3.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g3.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g3.Clear([System.Drawing.Color]::Transparent)
        $gp = New-Object System.Drawing.Drawing2D.GraphicsPath
        $gp.AddEllipse(1, 1, $legSize - 2, $legSize - 2)
        $g3.SetClip($gp)
        $g3.Clear($bgSample)
        $rndEmblem = [int][Math]::Round($legSize * 0.72)
        $rndOff = [int][Math]::Round(($legSize - $rndEmblem) / 2.0)
        $g3.DrawImage($fgSrc, (New-Object System.Drawing.Rectangle($rndOff, $rndOff, $rndEmblem, $rndEmblem)), $cropRect, [System.Drawing.GraphicsUnit]::Pixel)
        $gp.Dispose()
        $g3.Dispose()
        $rndBmp.Save((Join-Path $dir "ic_launcher_round.png"), [System.Drawing.Imaging.ImageFormat]::Png)

        $legBmp.Dispose()
        $rndBmp.Dispose()
    }

    $fgSrc.Dispose()
    Write-Host "Generated Android launcher icons successfully across mdpi..xxxhdpi."
} finally {
    $srcBmp.Dispose()
}
