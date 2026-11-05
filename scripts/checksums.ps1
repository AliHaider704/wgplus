# Prints the SHA-256 of release APKs so it can be pasted into the release notes.
Get-ChildItem (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist') -Filter *.apk | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
}
