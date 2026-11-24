<#
.SYNOPSIS
    Build script for Secure Document Vault Desktop (Windows).
.DESCRIPTION
    Uses PyInstaller to package the PySide6 application into a standalone executable.
#>

$ErrorActionPreference = "Stop"

Write-Host " Secure Document Vault - Windows Build " -ForegroundColor Cyan

# 1. Ensure PyInstaller and dependencies are installed
Write-Host "Installing dependencies from requirements-desktop.txt..." -ForegroundColor Yellow
pip install -r requirements-desktop.txt

# 2. Clean previous builds
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }

# 3. Run PyInstaller
# Note: --add-data bundles the 'src' folder so PyInstaller includes the crypto modules.
Write-Host "Packaging application..." -ForegroundColor Yellow
pyinstaller --noconfirm --onedir --windowed `
    --name "SecureDocumentVault" `
    --add-data "src;src" `
    --hidden-import "cryptography" `
    --hidden-import "ecies" `
    --hidden-import "coincurve" `
    desktop/__main__.py

Write-Host "Build Complete!" -ForegroundColor Green
Write-Host "Executable located at: dist\SecureDocumentVault\SecureDocumentVault.exe"