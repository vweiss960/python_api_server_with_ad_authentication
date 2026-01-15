# Windows Environment Variables - Quick Reference

Quick commands for setting environment variables when testing AD authentication on Windows.

## TL;DR - Quickest Way

### Command Prompt (cmd.exe)
```cmd
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!"
```

### PowerShell
```powershell
$env:AD_PASSWORD = "T3est123!!"
$env:JWT_SECRET = "my_super_secret_jwt_string"
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!"
```

## What You're Setting

- `AD_PASSWORD`: Password for your AD service account
  - For testing: `T3est123!!` (test admin user password)
  - For production: Your actual AD service account password

- `JWT_SECRET`: Secret key for signing JWT tokens
  - For testing: Any string (e.g., `my_super_secret_jwt_string`)
  - For production: Generate with `openssl rand -hex 32` or use a secure random string

## Common Tasks

### 1. Test AD Connectivity
```cmd
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
python tools/ad_auth_test.py --config config/config.test.yaml --verbose
```

### 2. Run API Server
```cmd
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
python -m src.main --config config/config.test.yaml
```

### 3. Test with Admin User
```cmd
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!" --verbose
```

### 4. Test with Read-Only User
```cmd
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
python tools/ad_auth_test.py --config config/config.test.yaml --username bro --password "T3est1234!!" --verbose
```

## Verify Variables Are Set

### Command Prompt
```cmd
echo %AD_PASSWORD%
echo %JWT_SECRET%
```

### PowerShell
```powershell
Write-Host $env:AD_PASSWORD
Write-Host $env:JWT_SECRET
```

## Batch Script for Testing

Save as `test_ad.bat`:
```batch
@echo off
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
call venv\Scripts\activate.bat
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!" --verbose
pause
```

Run with: `test_ad.bat`

## Batch Script for Running Server

Save as `run_server.bat`:
```batch
@echo off
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string
call venv\Scripts\activate.bat
python -m src.main --config config/config.test.yaml
```

Run with: `run_server.bat`

## PowerShell Script for Testing

Save as `test_ad.ps1`:
```powershell
$env:AD_PASSWORD = "T3est123!!"
$env:JWT_SECRET = "my_super_secret_jwt_string"
.\venv\Scripts\Activate.ps1
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!" --verbose
Read-Host "Press Enter to exit"
```

Run with: `.\test_ad.ps1`

## PowerShell Script for Running Server

Save as `run_server.ps1`:
```powershell
$env:AD_PASSWORD = "T3est123!!"
$env:JWT_SECRET = "my_super_secret_jwt_string"
.\venv\Scripts\Activate.ps1
python -m src.main --config config/config.test.yaml
```

Run with: `.\run_server.ps1`

## Environment Variables from File

Create `.env.local` (not in git):
```
AD_PASSWORD=T3est123!!
JWT_SECRET=my_super_secret_jwt_string
```

### Load in Command Prompt

Create `load_env.bat`:
```batch
@echo off
for /f "delims==" %%i in (type .env.local) do set %%i
echo Environment variables loaded from .env.local
```

Use it:
```batch
call load_env.bat
python -m src.main --config config/config.test.yaml
```

### Load in PowerShell

Create `load_env.ps1`:
```powershell
$EnvContent = Get-Content .env.local
foreach ($line in $EnvContent) {
    if ($line -match '(.+)=(.+)') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
Write-Host "Environment variables loaded from .env.local"
```

Use it:
```powershell
.\load_env.ps1
python -m src.main --config config/config.test.yaml
```

## Test Domain Credentials

**Admin User:**
- Username: `mtau` or `MTD\mtau` or `mtau@mytestdomain.com`
- Password: `T3est123!!`

**Read-Only User:**
- Username: `bro` or `MTD\bro` or `bro@mytestdomain.com`
- Password: `T3est1234!!`

## Troubleshooting

**"Environment variable not found"** error?
1. Make sure you set it with `set AD_PASSWORD=value` or `$env:AD_PASSWORD = "value"`
2. Verify it's set with echo/Write-Host
3. Make sure you're not in a different terminal window (each terminal has its own session)

**Can't run .ps1 script?**
Open PowerShell as Administrator and run:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## More Information

- For detailed setup: See [WINDOWS_SETUP.md](WINDOWS_SETUP.md)
- For all options: See [README.md](README.md)
- For API testing: See [README.md#testing-with-curl](README.md#testing-with-curl)
