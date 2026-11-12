<#
.SYNOPSIS
    Moves the frequent writes of ClipWarden onto a memory disk.

.DESCRIPTION
    The build, the temporary files, the log file and the data folder of the
    web view are written again and again. On a normal disk that wears the
    SSD out, and a memory disk is also faster.

    The software knows nothing about a particular disk: it uses the
    environment variables that are set here.

      CARGO_TARGET_DIR            the build output
      TEMP, TMP                   the temporary files of the compiler
      CLIPWARDEN_LOG_DIR           the log file of the service
      WEBVIEW2_USER_DATA_FOLDER   the cache of the dashboard

.EXAMPLE
    pwsh scripts\setup-ram-disk.ps1
#>
[CmdletBinding()]
param(
    # The memory disk and the folder that holds the data of ClipWarden.
    [string]$Drive = 'R:',
    [string]$Folder = 'ClipWarden'
)

$ErrorActionPreference = 'Stop'
$root = Join-Path $Drive $Folder

Write-Host "==> Preparing $root" -ForegroundColor Cyan

$folders = @{
    'build'  = Join-Path $root 'build'
    'temp'   = Join-Path $root 'temp'
    'log'    = Join-Path $root 'log'
    'webview' = Join-Path $root 'webview'
}
foreach ($entry in $folders.GetEnumerator()) {
    New-Item -ItemType Directory -Force -Path $entry.Value | Out-Null
    Write-Host "    $($entry.Key): $($entry.Value)"
}

# The launcher sets the environment variables and starts the dashboard.
$launcher = Join-Path $root 'start-clipwarden.cmd'
@"
@echo off
rem The folders that are written often live on the memory disk.
set "CARGO_TARGET_DIR=$($folders['build'])"
set "TEMP=$($folders['temp'])"
set "TMP=$($folders['temp'])"
set "CLIPWARDEN_LOG_DIR=$($folders['log'])"
set "WEBVIEW2_USER_DATA_FOLDER=$($folders['webview'])"
"%~dp0clipwarden-desktop.exe"
"@ | Set-Content -Path $launcher -Encoding ASCII
Write-Host "`n==> The launcher was written: $launcher" -ForegroundColor Green
Write-Host "    start it with that file, or set the variables by hand:"
Write-Host "      `$env:CARGO_TARGET_DIR = '$($folders['build'])'"
Write-Host "      `$env:TEMP = '$($folders['temp'])'"
Write-Host "      `$env:CLIPWARDEN_LOG_DIR = '$($folders['log'])'"
Write-Host "      `$env:WEBVIEW2_USER_DATA_FOLDER = '$($folders['webview'])'"
