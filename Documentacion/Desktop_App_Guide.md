# Secure Document Vault - Desktop App Guide

## Overview
This application provides a Graphical User Interface (GUI) for the Secure Document Vault engine (D2-D6). It allows users to encrypt, decrypt, manage keys, and verify document signatures using a PySide6 interface.

## Prerequisites
- Python 3.10 or higher
- Windows 10/11 (for the packaging script)

## Installation (Development Mode)
1. Clone the repository.
2. Create a virtual environment: `python -m venv venv`
3. Activate it: `.\venv\Scripts\activate`
4. Install dependencies: `pip install -r requirements-desktop.txt`
5. Run the app: `python -m desktop`

## Local Data Storage
By default, the application stores its encrypted keystores, configurations, and the D6 registry in the user's local AppData folder. The specific path is dynamically managed by `DesktopContext` using `QSettings` (Group: `Cripto-Team-1-Group-2`). 
*(Note: Data is intentionally kept outside the repository for security. You can change the directory via the "Settings" view).*

## Features
- **Home**: Dashboard and local environment status.
- **Documents**: Select and stage local files for operations.
- **Encrypt/Decrypt**: Multi-recipient encryption (min 2) and secure decryption.
- **My Keys**: *(Status: Under development by Yuki)* Will allow key rotation, revocation, and backup management in the next iteration.
- **Signatures**: Verify D5 signed containers against the live D6 revocation registry.


## Packaging for Windows (Production)
To generate a standalone executable, run the following in PowerShell (Administrator):
```powershell
.\packaging\build_windows.ps1
```
The executable will be available at dist\SecureDocumentVault\SecureDocumentVault.exe.

## Security Limitations

  

   * The application does not sync to the cloud.
   * Passwords are requested via UI dialogs only; they are never saved to disk or passed via command line.
   * Revoked keys are enforced by the underlying D6 engine and cannot be bypassed via the UI.

 
