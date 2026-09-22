# Packages the solution into solution.zip per the spec (section 7.1):
# source code and config only, no binaries, .git, datasets or IDE/build dirs.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/package.ps1

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'solution.zip'

# Paths that must NOT be included in the archive.
$excludePatterns = @(
    '\\\.git($|\\)', '\\bin($|\\)', '\\build($|\\)', '\\dist($|\\)',
    '\\out($|\\)', '\\obj($|\\)', '\\node_modules($|\\)', '\\for_agent($|\\)',
    '\\\.idea($|\\)', '\\\.vscode($|\\)', '\\tmp($|\\)'
)

if (Test-Path $out) { Remove-Item $out -Force }

$files = Get-ChildItem -Path $root -Recurse -File | Where-Object {
    $rel = $_.FullName.Substring($root.Length)
    if ($_.Extension -eq '.zip') { return $false }
    if ($_.Name -eq 'review.md') { return $false }
    foreach ($p in $excludePatterns) { if ($rel -match $p) { return $false } }
    return $true
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($out, 'Create')
try {
    foreach ($f in $files) {
        $entry = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $entry) | Out-Null
    }
} finally {
    $zip.Dispose()
}

Write-Output ("Created {0} ({1} files)" -f $out, $files.Count)
