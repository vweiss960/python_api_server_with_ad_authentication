# API Server with Active Directory Authentication

A production-ready REST API server built with FastAPI that provides Active Directory (LDAP) authentication and group-based authorization. Perfect for enterprise environments requiring secure API access with AD integration.

## Features

- **Active Directory Authentication**: Support for multiple username formats (sAMAccountName, Domain\Username, UserPrincipalName)
- **JWT Tokens**: Stateless authentication with group memberships cached in tokens
- **Group-Based Authorization**: Flexible group-based access control with AND/OR/NOT logic
- **TLS/HTTPS Support**: Configurable certificates with custom CA support
- **Structured Logging**: JSON formatted logs with request tracking
- **Configuration Management**: YAML-based configuration with environment variable overrides
- **Easy Integration**: Decorators for protecting routes with group requirements
- **Comprehensive Testing**: Standalone utility for testing AD connectivity and user authentication

## Quick Start

### Prerequisites

- Python 3.9+
- Active Directory server (optional, for testing without AD see development mode)
- OpenSSL (for generating test certificates)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd python_api_server_with_ad_authentication
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a configuration file (see Configuration section):
```bash
cp config/config.example.yaml config/config.yaml
# Edit config/config.yaml with your AD settings
```

5. Set environment variables:
```bash
export AD_PASSWORD=your_ad_password
export JWT_SECRET=your_jwt_secret_key
```

6. Run the server:
```bash
python -m src.main --config config/config.yaml
```

The API will be available at `https://localhost:8443` (or `http://localhost:8443` if TLS disabled).

## Configuration

### Configuration File Structure

Create a `config.yaml` file based on the provided example:

```yaml
server:
  host: 0.0.0.0
  port: 8443
  tls_enabled: true
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem

ad:
  server: ldap://ad.example.com:389
  use_ssl: false
  base_dn: DC=example,DC=com
  bind_dn: CN=service_account,OU=Users,DC=example,DC=com
  bind_password: ${AD_PASSWORD}
  user_search_filter: "(&(objectClass=user)(sAMAccountName={username}))"
  group_base_dn: OU=Groups,DC=example,DC=com
  group_attribute: memberOf

authorization:
  use_simple_names: true
  rules:
    - path: /api/admin/*
      groups: ["API-Admins"]
      require: any
    - path: /api/data/write
      groups: ["Data-Writers"]
      require: any
    - path: /api/data/read
      groups: ["Data-Readers", "Data-Writers"]
      require: any

jwt:
  secret: ${JWT_SECRET}
  expiration_hours: 24
  include_groups: true

certificates:
  custom_ca_dir: /path/to/custom_cas/
```

### Environment Variables

Sensitive values should be provided via environment variables:

- `AD_PASSWORD`: Password for the AD service account
- `JWT_SECRET`: Secret key for signing JWT tokens

Reference them in config with `${VARIABLE_NAME}` syntax.

### Supported Username Formats

The server supports three username formats for authentication:

1. **sAMAccountName**: `mtau`
2. **Domain\Username**: `DOMAIN\mtau`
3. **UserPrincipalName (UPN)**: `mtau@example.com`

The server automatically detects and normalizes the format.

## API Endpoints

### Public Endpoints (No Authentication Required)

#### Health Check
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00"
}
```

#### Login
```bash
POST /auth/login
Content-Type: application/json

{
  "username": "mtau",
  "password": "password123"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "username": "mtau",
    "dn": "CN=My User,OU=Users,DC=example,DC=com",
    "display_name": "My User",
    "email": "mtau@example.com",
    "groups": ["API-Admins", "Domain Users"]
  },
  "expires_in": 24
}
```

### Protected Endpoints (Authentication Required)

All protected endpoints require the `Authorization` header with a valid JWT token:

```bash
Authorization: Bearer <token>
```

#### Get User Info
```bash
GET /api/user/info
```

Response:
```json
{
  "username": "mtau",
  "display_name": "My User",
  "email": "mtau@example.com",
  "groups": ["API-Admins"]
}
```

#### Get User Groups
```bash
GET /api/user/groups
```

Response:
```json
{
  "username": "mtau",
  "groups": ["API-Admins", "Domain Users"],
  "group_count": 2
}
```

### Group-Protected Endpoints

These endpoints require specific group membership:

#### Read Data (Requires Data-Readers OR Data-Writers)
```bash
GET /api/data/read
```

#### Write Data (Requires Data-Writers)
```bash
POST /api/data/write
```

#### Admin Endpoints (Requires API-Admins)
```bash
GET /api/admin/users
DELETE /api/admin/users/{user_id}
GET /api/admin/settings
```

#### Get Authorization Rules (Admin Only)
```bash
GET /api/admin/rules
```

Response:
```json
{
  "rules": [
    {
      "path": "/api/admin/*",
      "groups": ["API-Admins"],
      "require": "any",
      "exclude_groups": null
    }
  ],
  "rule_count": 1
}
```

#### Check User Access (Admin Only)
```bash
POST /api/admin/check-access
Content-Type: application/json

{
  "path": "/api/data/write"
}
```

Response:
```json
{
  "path": "/api/data/write",
  "authorized": true,
  "required_groups": ["Data-Writers"],
  "message": null
}
```

## Adding New Endpoints

### Simple Protected Endpoint

```python
from fastapi import APIRouter, Request
from src.decorators.auth_decorators import require_auth

router = APIRouter()

@router.get("/api/my-endpoint")
@require_auth
async def my_endpoint(request: Request):
    user = request.state.user
    return {
        "message": "Hello " + user.get("sub"),
        "your_groups": user.get("groups", [])
    }
```

### Endpoint Requiring Specific Groups

```python
from src.decorators.auth_decorators import require_any_group

@router.post("/api/sensitive-operation")
@require_auth
@require_any_group(["Admins", "PowerUsers"])
async def sensitive_operation(request: Request):
    # Only users in Admins OR PowerUsers group can access
    return {"status": "success"}
```

### Endpoint Requiring All Groups

```python
from src.decorators.auth_decorators import require_groups

@router.delete("/api/critical-resource")
@require_auth
@require_groups(["Admins", "Approvers"])
async def delete_critical(request: Request):
    # User must be in BOTH Admins AND Approvers groups
    return {"status": "deleted"}
```

### Endpoint with Group Exclusions

```python
from src.decorators.auth_decorators import require_not_in_group

@router.get("/api/public-data")
@require_auth
@require_not_in_group(["Restricted-Users"])
async def get_public_data(request: Request):
    # Authenticated users who are NOT in Restricted-Users group
    return {"data": "public information"}
```

## Testing

### Testing with the AD Auth Test Utility

The included `ad_auth_test.py` utility helps test AD connectivity and authentication:

#### Interactive Mode
```bash
python tools/ad_auth_test.py
```

#### Command-Line Mode
```bash
python tools/ad_auth_test.py \
  --server ldap://mytestdomain.com:389 \
  --base-dn "DC=mytestdomain,DC=com" \
  --username mtau \
  --password "T3est123!!" \
  --verbose
```

#### Load Configuration from File
```bash
python tools/ad_auth_test.py \
  --config config/config.test.yaml \
  --username mtau \
  --password "T3est123!!"
```

#### Check Group Membership
```bash
python tools/ad_auth_test.py \
  --config config/config.test.yaml \
  --username mtau \
  --password "T3est123!!" \
  --check-group "admin_users"
```

#### Export Results
```bash
python tools/ad_auth_test.py \
  --config config/config.test.yaml \
  --username mtau \
  --password "T3est123!!" \
  --output test_result.json
```

### Comprehensive API Endpoint Tests

Run full endpoint test suite with different user groups:

```bash
python tests/test_api_endpoints.py
```

This tests:
- Public endpoints (health, login)
- Authentication with admin and read-only users
- User info endpoints (requires auth, no group restrictions)
- Data read endpoints (requires Data-Readers OR Data-Writers)
- Data write endpoints (requires Data-Writers)
- Admin endpoints (requires API-Admins group)
- Authorization failures and edge cases

Test users from `.env`:
- Admin user (admin_users group): Full access to all endpoints
- Read-Only user (ro_users group): Read access only

The script automatically:
- Loads test credentials from `.env` file
- Starts the API server if not running
- Tests all endpoints with both users
- Cleans up gracefully after tests complete
- Reports pass/fail for each endpoint

### Testing with cURL

#### Login and Get Token
```bash
curl -X POST http://localhost:8443/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mtau",
    "password": "T3est123!!"
  }' \
  -k  # Skip SSL verification for self-signed certs
```

#### Use Token to Access Protected Endpoint
```bash
TOKEN="your_token_here"

curl -X GET http://localhost:8443/api/user/info \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

#### Test Admin Endpoint (Should Fail Without Proper Group)
```bash
curl -X GET http://localhost:8443/api/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

Expected response with insufficient permissions:
```json
{
  "error": "http_error",
  "message": "Insufficient permissions. Required groups: [\"API-Admins\"]"
}
```

## Test Domain (mytestdomain.com)

A test configuration is provided for the mytestdomain.com test Active Directory domain.

### Test Users

**Admin User**
- sAMAccountName: `mtau`
- Domain\Username: `MTD\mtau`
- UserPrincipalName: `mtau@mytestdomain.com`
- Password: `T3est123!!`
- Groups: `admin_users`

**Read-Only User**
- sAMAccountName: `bro`
- Domain\Username: `MTD\bro`
- UserPrincipalName: `bro@mytestdomain.com`
- Password: `T3est1234!!`
- Groups: `ro_users`

### Test Configuration

Use the provided `config/config.test.yaml`:

```bash
export AD_PASSWORD=T3est123!!
export JWT_SECRET=test_secret_key_change_in_production
python -m src.main --config config/config.test.yaml
```

### Test Scenarios

**Admin User Can Access Admin Endpoints:**
```bash
# Login as admin user
TOKEN=$(curl -s -X POST http://localhost:8443/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"mtau","password":"T3est123!!"}' \
  -k | jq -r '.token')

# Access admin endpoint - should succeed
curl -X GET http://localhost:8443/api/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

**Read-Only User Cannot Access Admin Endpoints:**
```bash
# Login as read-only user
TOKEN=$(curl -s -X POST http://localhost:8443/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"bro","password":"T3est1234!!"}' \
  -k | jq -r '.token')

# Try to access admin endpoint - should return 403
curl -X GET http://localhost:8443/api/admin/users \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

**Both Users Can Read Data:**
```bash
# Both admin and read-only users can access /api/data/read
curl -X GET http://localhost:8443/api/data/read \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

**Only Admin Can Write Data:**
```bash
# Only admin user (in Data-Writers group) can write
curl -X POST http://localhost:8443/api/data/write \
  -H "Authorization: Bearer $TOKEN" \
  -k
```

## Development Mode

For local development without TLS or a real AD server, you can run in development mode:

```yaml
server:
  tls_enabled: false
  host: 127.0.0.1
  port: 8000

# Note: You still need a valid AD configuration, or mock it for testing
```

Then run:
```bash
python -m src.main --config config/config.yaml --port 8000
```

Access at `http://localhost:8000`

## Generating Self-Signed Certificates

For testing with TLS:

```bash
# Generate private key (4096-bit RSA)
openssl genrsa -out server.key 4096

# Generate certificate signing request
openssl req -new -key server.key -out server.csr

# Generate self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Combine into PEM format (if needed)
cat server.crt server.key > server.pem
```

Update your config to use:
```yaml
server:
  tls_enabled: true
  cert_file: /path/to/server.crt
  key_file: /path/to/server.key
```

## Docker Deployment

### Build Image
```bash
docker build -t api-server:latest -f docker/Dockerfile .
```

### Run Container
```bash
docker run -d \
  --name api-server \
  -p 8443:8443 \
  -e AD_PASSWORD=your_password \
  -e JWT_SECRET=your_secret \
  -v $(pwd)/config/config.docker.yaml:/app/config/config.docker.yaml \
  api-server:latest
```

### Check Logs
```bash
docker logs -f api-server
```

## Systemd Deployment (Linux)

### Installation

1. Create application directory:
```bash
sudo mkdir -p /opt/api-server
sudo chown -R appuser:appuser /opt/api-server
```

2. Copy files:
```bash
sudo cp -r src config requirements.txt /opt/api-server/
sudo chown -R appuser:appuser /opt/api-server
```

3. Create virtual environment:
```bash
cd /opt/api-server
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. Copy systemd service file:
```bash
sudo cp systemd/api-server.service /etc/systemd/system/
sudo systemctl daemon-reload
```

5. Set environment variables:
```bash
sudo nano /etc/default/api-server
# Add: export AD_PASSWORD=...
# Add: export JWT_SECRET=...
```

6. Enable and start:
```bash
sudo systemctl enable api-server
sudo systemctl start api-server
sudo systemctl status api-server
```

7. View logs:
```bash
sudo journalctl -u api-server -f
```

## Logging

All requests and authentication events are logged in JSON format for easy parsing and analysis.

### Log Levels

Set in code (future: configurable):
- DEBUG: Detailed debugging information
- INFO: General information about application operation
- WARNING: Warning messages for potentially problematic situations
- ERROR: Error messages for serious problems

### Log Format

Each log entry is a JSON object with:
```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "level": "INFO",
  "logger": "api_server.routes.auth",
  "message": "User mtau successfully logged in",
  "user": "mtau",
  "request_id": "uuid",
  "status_code": 200,
  "response_time_ms": 145.23
}
```

## Security Considerations

### Best Practices

1. **Never commit credentials**: Always use environment variables
2. **Restrict certificate permissions**: Key files should be readable only by the application user
3. **Use strong JWT secrets**: Generate with `openssl rand -hex 32`
4. **Enable HTTPS in production**: TLS is required for security
5. **Regular updates**: Keep dependencies updated for security patches
6. **Monitor logs**: Review authentication failures and authorization denials
7. **Service account permissions**: Limit AD service account permissions (read-only)
8. **Token expiration**: Adjust JWT expiration based on security requirements
9. **Rate limiting**: Consider adding rate limiting to login endpoint in production
10. **CORS**: Configure CORS settings if frontend is on different domain

### Password Security

- Passwords are never logged
- Passwords are transmitted over HTTPS only (in production)
- User credentials are verified directly against AD, not stored locally

## Troubleshooting

### Connection to AD Server Fails

```
Error: AD connection failed
```

**Solutions:**
1. Check server address and port: `ldap://ad.example.com:389`
2. Verify network connectivity: `ping ad.example.com`
3. Check firewall rules allow access to LDAP port
4. Test with ad_auth_test.py: `python tools/ad_auth_test.py --server ldap://...`

### Invalid Service Account Credentials

```
Error: Service account credentials invalid
```

**Solutions:**
1. Verify bind_dn is correct format: `CN=account,OU=Users,DC=example,DC=com`
2. Check password is correct
3. Verify account has permissions to search users and groups
4. Test with: `ldapsearch -x -h ad.example.com -D "bind_dn" -W`

### User Not Found

```
Error: User not found in AD
```

**Solutions:**
1. Verify username format (try different formats)
2. Check base_dn includes user's OU
3. Verify user_search_filter is correct
4. Test with ad_auth_test.py to see search results

### Invalid Credentials Error

```
Error: Invalid credentials
```

**Solutions:**
1. Verify password is correct
2. Try with different username formats
3. Check user account is not locked or disabled in AD
4. Verify account has login permissions

### Group Membership Not Retrieved

**Solutions:**
1. Verify group_search_filter is correct
2. Check group_base_dn includes group's OU
3. Verify user actually belongs to groups in AD
4. Check group attribute name (usually "memberOf")

## Architecture

```
src/
├── main.py                  # FastAPI app entry point
├── config.py               # Configuration loading
├── models.py               # Pydantic models
├── security/
│   ├── auth.py            # LDAP authentication
│   ├── authorization.py   # Group-based authorization
│   ├── jwt_handler.py     # JWT token management
├── api/
│   ├── health_routes.py   # Health check
│   ├── auth_routes.py     # Login endpoint
│   ├── user_routes.py     # User info endpoints
│   ├── data_routes.py     # Data access endpoints
│   └── admin_routes.py    # Admin endpoints
├── middleware/
│   ├── auth_middleware.py     # JWT validation
│   └── logging_middleware.py  # Request logging
├── decorators/
│   └── auth_decorators.py # @require_auth, @require_groups
└── utils/
    ├── logger.py          # Structured logging
    └── errors.py          # Custom exceptions
```

## License

[Specify your license here]

## Support

For issues and questions:
1. Check troubleshooting section
2. Review logs for error details
3. Test with ad_auth_test.py utility
4. Open an issue on GitHub

## Contributing

[Add contribution guidelines if applicable]
