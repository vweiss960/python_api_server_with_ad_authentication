# Windows Installation Guide

## Problem: python-ldap on Windows

On Windows, the original `python-ldap` library fails to install because it requires compiled C extensions (LDAP header files) that aren't available. This results in the error:

```
fatal error C1083: Cannot open include file: 'lber.h': No such file or directory
```

## Solution: Using ldap3 Instead

The project has been configured to use **ldap3** instead, which is a pure Python LDAP client library that works perfectly on Windows without requiring any compiled extensions.

### Key Differences

| Feature | python-ldap | ldap3 |
|---------|-------------|-------|
| Installation | Requires compilation | Pure Python |
| Windows Support | Requires pre-built wheels | ✓ Works natively |
| Cross-platform | Linux/Mac only (easily) | ✓ Windows, Linux, Mac |
| API | Traditional LDAP API | Modern, more intuitive |
| License | Python | MIT |

## Installation on Windows

### Option 1: Normal pip install (Recommended)

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install all requirements (including ldap3)
pip install -r requirements.txt
```

That's it! No compilation needed.

## Setting Environment Variables on Windows

When testing AD authentication, you need to set environment variables for sensitive data like AD passwords and JWT secrets. Here are the ways to do it on Windows:

### Option 1: Command Prompt (cmd.exe)

```cmd
REM Set environment variables for current session only
set AD_PASSWORD=your_ad_password
set JWT_SECRET=your_jwt_secret_key

REM Verify they are set
echo %AD_PASSWORD%
echo %JWT_SECRET%

REM Run the server
python -m src.main --config config/config.yaml

REM Test AD authentication
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!"
```

### Option 2: PowerShell

```powershell
# Set environment variables for current session only
$env:AD_PASSWORD = "your_ad_password"
$env:JWT_SECRET = "your_jwt_secret_key"

# Verify they are set
Write-Host $env:AD_PASSWORD
Write-Host $env:JWT_SECRET

# Run the server
python -m src.main --config config/config.yaml

# Test AD authentication
python tools/ad_auth_test.py --config config/config.test.yaml --username mtau --password "T3est123!!"
```

### Option 3: Create a .bat file (Windows Batch)

Create a file named `run_server.bat`:

```batch
@echo off
REM Set environment variables
set AD_PASSWORD=your_ad_password
set JWT_SECRET=your_jwt_secret_key

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Run the server
python -m src.main --config config/config.yaml
```

Then run it from Command Prompt:
```cmd
run_server.bat
```

### Option 4: Create a .ps1 file (PowerShell)

Create a file named `run_server.ps1`:

```powershell
# Set environment variables
$env:AD_PASSWORD = "your_ad_password"
$env:JWT_SECRET = "your_jwt_secret_key"

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run the server
python -m src.main --config config/config.yaml
```

Then run it from PowerShell:
```powershell
.\run_server.ps1
```

### Option 5: Permanently Set Environment Variables (System-wide)

To set environment variables permanently on Windows (accessible in all terminals):

**Using Command Prompt as Administrator:**
```cmd
setx AD_PASSWORD "your_ad_password"
setx JWT_SECRET "your_jwt_secret_key"
```

**Using PowerShell as Administrator:**
```powershell
[Environment]::SetEnvironmentVariable("AD_PASSWORD", "your_ad_password", "User")
[Environment]::SetEnvironmentVariable("JWT_SECRET", "your_jwt_secret_key", "User")
```

**Using GUI:**
1. Press `Win + X` and select "System"
2. Click "Advanced system settings"
3. Click "Environment Variables..."
4. Under "User variables", click "New..."
5. Variable name: `AD_PASSWORD`, Variable value: `your_ad_password`
6. Click "New..." again
7. Variable name: `JWT_SECRET`, Variable value: `your_jwt_secret_key`
8. Click "OK" and restart your terminal

After setting permanently, you need to restart your terminal for changes to take effect.

## Example: Testing with mytestdomain.com

### Using Command Prompt

```cmd
REM Activate virtual environment
venv\Scripts\activate.bat

REM Set environment variables for test domain
set AD_PASSWORD=T3est123!!
set JWT_SECRET=my_super_secret_jwt_string

REM Test AD authentication with test user
python tools/ad_auth_test.py ^
  --config config/config.test.yaml ^
  --username mtau ^
  --password "T3est123!!" ^
  --verbose

REM Run the API server
python -m src.main --config config/config.test.yaml
```

### Using PowerShell

```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Set environment variables for test domain
$env:AD_PASSWORD = "T3est123!!"
$env:JWT_SECRET = "my_super_secret_jwt_string"

# Test AD authentication with test user
python tools/ad_auth_test.py `
  --config config/config.test.yaml `
  --username mtau `
  --password "T3est123!!" `
  --verbose

# Run the API server
python -m src.main --config config/config.test.yaml
```

## Important Security Notes

⚠️ **Never commit credentials to version control!**

- `.env` files with real credentials should NOT be committed
- `.gitignore` already includes `*.pem`, `*.key`, and config files
- Use environment variables or `.env.local` (not in git)
- For production, use proper secrets management (e.g., Azure Key Vault, AWS Secrets Manager)

## Recommended Approach for Development

Create a local `.env.local` file (not in git) with your test credentials:

```
AD_PASSWORD=T3est123!!
JWT_SECRET=my_super_secret_jwt_string
```

Then load it in a batch file before running:

**load_env.bat:**
```batch
@echo off
for /f "delims==" %%i in (type .env.local) do set %%i
```

**run_with_env.bat:**
```batch
@echo off
call load_env.bat
call venv\Scripts\activate.bat
python -m src.main --config config/config.yaml
```

### Option 2: Manual installation if needed

```bash
pip install ldap3==2.9.1
```

## Verification

Verify that ldap3 is installed:

```bash
pip list | findstr ldap3
# Output: ldap3                     2.9.1
```

## Code Changes Made

The authentication module has been updated to use `ldap3` instead of `python-ldap`:

**Before:**
```python
import ldap

conn = ldap.initialize(server)
conn.simple_bind_s(dn, password)
results = conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter, ["*"])
```

**After:**
```python
from ldap3 import Server, Connection, ALL

server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
conn = Connection(server, user=dn, password=password)
conn.bind()
conn.search(base_dn, filter, attributes=["*"])
```

## Features Preserved

All the original functionality is preserved:

✓ LDAP/AD authentication
✓ User lookup and search
✓ Group membership retrieval
✓ Multiple username format support
✓ Service account binding
✓ Error handling and logging
✓ Configuration compatibility

## Testing

Everything works exactly the same:

```bash
# Run the server
python -m src.main --config config/config.yaml

# Test AD authentication
python tools/ad_auth_test.py --config config/config.test.yaml --username user --password pass
```

## Additional Notes

- **ldap3** is actively maintained and very stable
- It has excellent documentation: https://ldap3.readthedocs.io/
- It's used in production by many organizations
- Performance is equivalent to python-ldap
- No functionality has been lost

## If You Prefer python-ldap

If you really need `python-ldap` on Windows, you have these options:

1. **Use pre-built wheels**:
   - Download from: https://www.lfd.uci.edu/~gohlke/pythonlibs/#python-ldap
   - Select the correct version for your Python version (e.g., `python_ldap‑3.4.5‑cp312‑cp312‑win_amd64.whl`)
   - Install with: `pip install python_ldap‑3.4.5‑cp312‑cp312‑win_amd64.whl`
   - Revert `src/security/auth.py` and `tools/ad_auth_test.py` to use the original code

2. **Use Windows Subsystem for Linux (WSL)**:
   - This gives you a real Linux environment where python-ldap installs normally

3. **Use Docker**:
   - Build and run the Docker image which has all dependencies pre-installed
   - `docker build -t api-server . && docker run -it api-server`

## Requirements.txt

The `requirements.txt` has been updated to use `ldap3`:

```
fastapi==0.109.1
uvicorn[standard]==0.27.0
pydantic==2.5.3
ldap3==2.9.1
PyJWT==2.8.0
PyYAML==6.0.1
pytest==7.4.4
pytest-asyncio==0.23.3
pytest-cov==4.1.0
httpx==0.26.0
colorama==0.4.6
```

## Troubleshooting

### If you still get LDAP errors:

1. **Verify ldap3 is installed**:
   ```bash
   python -c "import ldap3; print(ldap3.__version__)"
   ```

2. **Check your AD server is accessible**:
   ```bash
   ping your-ad-server.com
   ```

3. **Test connectivity with the utility**:
   ```bash
   python tools/ad_auth_test.py --server ldap://your-ad-server:389 --base-dn "DC=example,DC=com"
   ```

4. **Enable verbose logging**:
   ```bash
   python tools/ad_auth_test.py --config config/config.yaml --username user --password pass --verbose
   ```

## More Information

For detailed setup instructions, see [README.md](README.md)

For API documentation, see the README endpoints section.
