@echo off
setlocal

cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference = 'Stop';" ^
  "$root = (Resolve-Path '.').Path;" ^
  "$releaseDir = Join-Path $root 'release';" ^
  "$stage = Join-Path $releaseDir 'js-analysis-engine';" ^
  "$stamp = Get-Date -Format 'yyyyMMdd-HHmmss';" ^
  "$zip = Join-Path $releaseDir ('js-analysis-engine-' + $stamp + '.zip');" ^
  "if (!(Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir | Out-Null };" ^
  "if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force };" ^
  "New-Item -ItemType Directory -Path $stage | Out-Null;" ^
  "$files = @('src', 'docs', 'config', 'package.json', 'package-lock.json', 'tsconfig.json', 'vitest.config.ts', '.gitignore', 'LICENSE');" ^
  "foreach ($file in $files) { if (Test-Path $file) { Copy-Item -LiteralPath $file -Destination $stage -Recurse -Force } };" ^
  "if (Test-Path 'README.md') { Copy-Item -LiteralPath 'README.md' -Destination $stage -Force };" ^
  "$stageItems = Join-Path $stage '*';" ^
  "Compress-Archive -Path $stageItems -DestinationPath $zip -Force;" ^
  "Remove-Item -LiteralPath $stage -Recurse -Force;" ^
  "Write-Host ('Created release package: ' + $zip);"

if errorlevel 1 (
  echo.
  echo Release package failed.
  exit /b 1
)

echo.
echo Release package is ready in the release directory.
endlocal
