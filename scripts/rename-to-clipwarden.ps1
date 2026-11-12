<#
.SYNOPSIS
    Renames the project from ClipWarden to ClipWarden.

.DESCRIPTION
    The rename touches many places: the crate names, the binaries, the pipe
    name, the mutexes, the registry value, the data folder, the application
    identifier and every text that mentions the product.

    The script does the work in three steps:

      1. every tracked file is searched for the three spellings and the
         spelling is replaced,
      2. the directories and the files that carry the name are renamed,
      3. the lock files are updated and the project is built.

    The data folder of the current installation is moved as well, so that the
    settings of the user survive the rename.

.EXAMPLE
    pwsh scripts\rename-to-clipwarden.ps1
#>
[CmdletBinding()]
param(
    [string]$Old = 'clipwarden',
    [string]$New = 'clipwarden',
    [string]$OldName = 'ClipWarden',
    [string]$NewName = 'ClipWarden',
    [string]$Root = '.'
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)

Write-Host "==> Renaming $OldName to $NewName" -ForegroundColor Cyan

# ---------------------------------------------------------------- the files
$files = git -C $Root ls-files | ForEach-Object { Join-Path $Root $_ }
$files += git -C $Root ls-files --others --exclude-standard | ForEach-Object { Join-Path $Root $_ }

$changed = 0
foreach ($file in $files) {
    if (-not (Test-Path $file)) { continue }
    if ([IO.Path]::GetExtension($file) -eq '.zip') { continue }
    $bytes = [IO.File]::ReadAllBytes($file)
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { continue }
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    if ($text -notmatch [regex]::Escape($Old) -and $text -notmatch [regex]::Escape($OldName)) { continue }
    $updated = $text.Replace($Old, $New).Replace($OldName, $NewName)
    [IO.File]::WriteAllText((Resolve-Path $file).Path, $updated, $utf8)
    $changed++
}
Write-Host "==> $changed file(s) updated"

# --------------------------------------------------------- the directories
Get-ChildItem -Path $Root -Recurse -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\target\\|\\\.git\\' } |
    Sort-Object { $_.FullName.Length } -Descending |
    ForEach-Object {
        $name = $_.Name
        if ($name -notmatch [regex]::Escape($Old) -and $name -notmatch [regex]::Escape($OldName)) { return }
        $newName = $name.Replace($Old, $New).Replace($OldName, $NewName)
        $target = Join-Path $_.Parent.FullName $newName
        if ($target -ne $_.FullName) {
            Rename-Item -Path $_.FullName -NewName $newName
            Write-Host "    folder: $name -> $newName"
        }
    }

# ------------------------------------------------------------- the files
Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\target\\|\\\.git\\' -and $_.Extension -ne '.zip' } |
    ForEach-Object {
        $name = $_.Name
        if ($name -notmatch [regex]::Escape($Old) -and $name -notmatch [regex]::Escape($OldName)) { return }
        $newName = $name.Replace($Old, $New).Replace($OldName, $NewName)
        Rename-Item -Path $_.FullName -NewName $newName
        Write-Host "    file:   $name -> $newName"
    }

# ---------------------------------------------------- the data of the user
$oldData = Join-Path $env:APPDATA $OldName
$newData = Join-Path $env:APPDATA $NewName
if ((Test-Path $oldData) -and -not (Test-Path $newData)) {
    Move-Item -Path $oldData -Destination $newData
    Write-Host "==> the settings were moved to $newData"
}

# ------------------------------------------------------------- the registry
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$oldValue = Get-ItemProperty -Path $runKey -Name $OldName -ErrorAction SilentlyContinue
if ($oldValue) {
    Set-ItemProperty -Path $runKey -Name $NewName -Value $oldValue.$OldName
    Remove-ItemProperty -Path $runKey -Name $OldName -ErrorAction SilentlyContinue
    Write-Host "==> the automatic start entry was renamed"
}

# ---------------------------------------------------------------- the build
Push-Location $Root
try {
    Write-Host "`n==> Updating the lock files" -ForegroundColor Cyan
    cargo update --workspace
    cargo update --manifest-path apps\desktop\src-tauri\Cargo.toml

    Write-Host "`n==> Building" -ForegroundColor Cyan
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw 'the build failed' }
    cargo build --release --manifest-path apps\desktop\src-tauri\Cargo.toml
    if ($LASTEXITCODE -ne 0) { throw 'the build of the dashboard failed' }

    Write-Host "`n==> Testing" -ForegroundColor Cyan
    cargo test --workspace
    if ($LASTEXITCODE -ne 0) { throw 'the tests failed' }
}
finally {
    Pop-Location
}

Write-Host "`n==> Done: $NewName" -ForegroundColor Green
