# API Server Requirements Specification

## Project Overview
Create a REST API server with Active Directory authentication, group-based authorization, TLS support, and custom certificate trust management.

## Core Requirements

### 1. Programming Language & Framework
- **Language**: Python with FastAPI
- **Rationale**: Easy to modify, well-documented, strong TLS/crypto support

### 2. Authentication
- Implement Active Directory (LDAP) authentication
- Support username/password authentication via HTTP Basic Auth or Bearer tokens
- Support multiple username formats:
  - sAMAccountName (e.g., `mtau`)
  - Domain\Username (e.g., `MTD\mtau`)
  - UserPrincipalName (e.g., `mtau@mytestdomain.com`)
- Validate credentials against AD server
- Configuration should include:
  - AD server hostname/IP
  - Base DN for user searches
  - Bind DN and password (service account)
  - User search filter template
  - Group search filter template
- Return JWT tokens after successful authentication
  - JWT should include user groups as claims
- Middleware/decorator to protect endpoints requiring authentication

### 3. Authorization (Group-Based Access Control)
- Query user's AD group memberships during authentication
- Store group memberships in JWT token claims
- Implement authorization middleware/decorator that:
  - Checks if user belongs to required group(s)
  - Supports multiple authorization models:
    - Require ANY of specified groups (OR logic)
    - Require ALL of specified groups (AND logic)
    - Require NOT in certain groups (exclusion)
- Configuration mapping endpoints to required groups:
```yaml
  authorization:
    group_attribute: memberOf  # AD attribute containing group DNs
    # Map endpoint patterns to required groups
    rules:
      - path: /api/admin/*
        groups: ["CN=API-Admins,OU=Groups,DC=example,DC=com"]
        require: any
      - path: /api/data/*
        groups: 
          - "CN=Data-Readers,OU=Groups,DC=example,DC=com"
          - "CN=Data-Writers,OU=Groups,DC=example,DC=com"
        require: any
      - path: /api/reports/*
        groups:
          - "CN=Report-Users,OU=Groups,DC=example,DC=com"
        exclude_groups:
          - "CN=Restricted-Users,OU=Groups,DC=example,DC=com"
        require: any
```
- Support for simple group name matching (not just full DNs)
- Return 403 Forbidden when user lacks required group membership

### 4. TLS/Certificate Management
- Server must support HTTPS with configurable certificates
- Configuration for:
  - Server certificate file path
  - Server private key file path
  - Optional: certificate chain/intermediate certs
- Support for adding custom root CAs:
  - Load custom CA certificates from a directory
  - Support both CA certificates and self-signed certificates
  - Use custom trust store when making outbound HTTPS requests
- Configuration should allow disabling TLS for development (with warning)

### 5. Configuration Management
- Use configuration file (YAML or JSON) for all settings
- Environment variable overrides for sensitive data
- Configuration structure:
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
    bind_password: ${AD_PASSWORD}  # from environment
    user_search_filter: "(&(objectClass=user)(sAMAccountName={username}))"
    group_base_dn: OU=Groups,DC=example,DC=com
    group_search_filter: "(&(objectClass=group)(member={user_dn}))"
    group_attribute: memberOf
    
  authorization:
    group_attribute: memberOf
    use_simple_names: true  # Extract CN from DN for matching
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
    
  certificates:
    custom_ca_dir: /path/to/custom_cas/
    
  jwt:
    secret: ${JWT_SECRET}
    expiration_hours: 24
    include_groups: true  # Include groups in JWT claims
```

### 6. API Endpoints
Implement the following example endpoints:

#### Public Endpoints (no auth required)
- `GET /health` - Health check endpoint
- `POST /auth/login` - Login endpoint (returns token with user info and groups)

#### Protected Endpoints (auth required, no specific group)
- `GET /api/user/info` - Return authenticated user information including groups
- `GET /api/user/groups` - Return user's AD group memberships

#### Group-Protected Endpoints (examples)
- `GET /api/data/read` - Requires "Data-Readers" OR "Data-Writers" group
- `POST /api/data/write` - Requires "Data-Writers" group
- `GET /api/admin/users` - Requires "API-Admins" group
- `DELETE /api/admin/users/{id}` - Requires "API-Admins" group

Make it easy to add new endpoints with decorator/middleware specifying required groups:
```python
# Python example
@app.get("/api/admin/settings")
@require_groups(["API-Admins"])
async def get_settings():
    ...

# or
@app.post("/api/data/write")
@require_any_group(["Data-Writers", "Data-Admins"])
async def write_data():
    ...
```

### 7. Logging
- Structured logging with configurable levels (DEBUG, INFO, WARN, ERROR)
- Log authentication attempts (success/failure) with username
- Log authorization checks (group membership validation)
- Log TLS connection details
- Log API requests with method, path, status code, response time, username
- Log authorization failures with required vs actual groups
- Sensitive data (passwords, tokens) should never be logged

### 8. Error Handling
- Proper HTTP status codes
- Consistent JSON error response format:
```json
  {
    "error": "error_type",
    "message": "Human readable message",
    "details": {}  # optional
  }
```
- Handle common scenarios:
  - Invalid credentials (401)
  - Missing authentication (401)
  - Forbidden access - insufficient group membership (403)
  - Not found (404)
  - Server errors (500)
- Authorization errors should indicate:
  - Which groups are required
  - That the user lacks necessary permissions (without revealing user's actual groups for security)

### 9. Code Organization
- Clear project structure with separate modules/packages for:
  - Configuration loading
  - Authentication logic (AD/LDAP)
  - Authorization logic (group checking)
  - TLS/certificate management
  - API route handlers
  - Middleware/decorators
- Include clear comments explaining key sections
- README with setup and usage instructions

### 10. Dependencies & Deployment
- Requirements/dependencies file (requirements.txt or go.mod)
- Dockerfile for containerization
- Example systemd service file for Linux deployment
- Development mode instructions (running without TLS locally)

### 11. Security Considerations
- No hardcoded credentials
- Secure password handling (never logged or stored)
- Rate limiting on authentication endpoint (basic implementation)
- CORS configuration (if needed)
- Security headers in responses
- JWT token validation on every protected request
- Proper group DN parsing and validation
- Cache group memberships in JWT (avoid LDAP query on every request)
- Token refresh mechanism (optional but recommended)

### 12. Testing & Examples
- Example configuration file with dummy values and group rules
- Shell script or curl commands demonstrating:
  - Login request (returns token with groups)
  - Authenticated API call with valid group membership
  - Authenticated API call with insufficient group membership (403)
  - Viewing user info including groups
- Instructions for testing with AD and setting up test groups
- Instructions for generating self-signed certificates for testing
- Mock AD responses for unit testing without real AD server

### 13. Administrative Features
- Endpoint to list all configured authorization rules (admin only)
- Endpoint to test if current user has access to a specific path (useful for UI)
- Clear error messages when group configuration is invalid

### 14. Test Domain Controller Configuration
Create configuration and test suite for testing against the following Active Directory domain controller:

**Domain**: mytestdomain.com

**Test Users and Groups**:
- **Admin User**:
  - Group: `admin_users`
  - Username: `my_test_admin_user`
  - Login formats supported:
    - `mtau` (sAMAccountName)
    - `MTD\mtau` (Domain\Username)
    - `mtau@mytestdomain.com` (UserPrincipalName)
  - Password: `T3est123!!`

- **Read-Only User**:
  - Group: `ro_users`
  - Username: `bob_read_only`
  - Login formats supported:
    - `bro` (sAMAccountName)
    - `MTD\bro` (Domain\Username)
    - `bro@mytestdomain.com` (UserPrincipalName)
  - Password: `T3est1234!!`

**Configuration File for Test Domain** (`config.test.yaml`):
```yaml
server:
  host: 0.0.0.0
  port: 8443
  tls_enabled: false  # Disabled for testing
  
ad:
  server: ldap://mytestdomain.com:389
  use_ssl: false
  base_dn: DC=mytestdomain,DC=com
  bind_dn: CN=my_test_admin_user,CN=Users,DC=mytestdomain,DC=com
  bind_password: ${AD_PASSWORD}  # T3est123!!
  user_search_filter: "(|(sAMAccountName={username})(userPrincipalName={username}))"
  group_base_dn: CN=Users,DC=mytestdomain,DC=com
  group_attribute: memberOf
  
authorization:
  use_simple_names: true
  rules:
    - path: /api/admin/*
      groups: ["admin_users"]
      require: any
    - path: /api/data/write
      groups: ["admin_users"]
      require: any
    - path: /api/data/read
      groups: ["admin_users", "ro_users"]
      require: any

jwt:
  secret: ${JWT_SECRET}
  expiration_hours: 24
  include_groups: true
```

**Test Suite Requirements**:
- Create automated test script that:
  - Tests authentication with both users using all three username formats
  - Verifies group memberships are correctly retrieved
  - Tests authorization for admin-only endpoints (mtau should succeed, bro should get 403)
  - Tests authorization for read-only endpoints (both should succeed)
  - Tests invalid credentials (should fail appropriately)
  - Generates a test report showing pass/fail for each test case

### 15. AD Authentication Test Utility
Create a standalone command-line utility for testing AD authentication:

**Utility Name**: `ad-auth-test` (or `ad_auth_test.py` / `ad-auth-test`)

**Features**:
- Interactive mode: Prompts for connection details and credentials
- Command-line mode: All parameters via CLI arguments
- Test multiple username formats automatically
- Retrieve and display user's group memberships
- Test bind authentication (service account)
- Colorized output for success/failure
- Verbose mode for debugging LDAP queries
- Support for both LDAP and LDAPS connections
- Test connectivity before attempting authentication

**Command-line Interface**:
```bash
# Interactive mode
./ad-auth-test

# Command-line mode with all parameters
./ad-auth-test \
  --server ldap://mytestdomain.com:389 \
  --base-dn "DC=mytestdomain,DC=com" \
  --username mtau \
  --password "T3est123!!" \
  --verbose

# Test service account bind
./ad-auth-test \
  --server ldap://mytestdomain.com:389 \
  --base-dn "DC=mytestdomain,DC=com" \
  --bind-dn "CN=my_test_admin_user,CN=Users,DC=mytestdomain,DC=com" \
  --bind-password "T3est123!!" \
  --test-bind

# Test from config file
./ad-auth-test --config config.test.yaml --username mtau --password "T3est123!!"
```

**Output Format**:
```
AD Authentication Test Utility
==============================

Connection Details:
  Server: ldap://mytestdomain.com:389
  Base DN: DC=mytestdomain,DC=com
  Use SSL: No

Testing connectivity... ✓ Connected

Testing authentication for user: mtau
  Format: sAMAccountName (mtau)... ✓ Success
  Format: Domain\Username (MTD\mtau)... ✓ Success
  Format: UserPrincipalName (mtau@mytestdomain.com)... ✓ Success

User Details:
  DN: CN=my_test_admin_user,CN=Users,DC=mytestdomain,DC=com
  Display Name: My Test Admin User
  Email: mtau@mytestdomain.com
  
Group Memberships (3):
  ✓ CN=admin_users,CN=Users,DC=mytestdomain,DC=com
  ✓ CN=Domain Users,CN=Users,DC=mytestdomain,DC=com
  ✓ CN=Users,CN=Builtin,DC=mytestdomain,DC=com

All tests passed! ✓
```

**Utility Features**:
- Connection timeout configuration
- SSL/TLS certificate verification options
- Export results to JSON format
- Batch testing mode (read credentials from file)
- Support for testing custom search filters
- Check if user is member of specific group
- List all groups in domain (optional, requires appropriate permissions)

**Usage Examples in README**:
```bash
# Quick test of mytestdomain.com setup
./ad-auth-test \
  --server ldap://mytestdomain.com:389 \
  --base-dn "DC=mytestdomain,DC=com" \
  --username mtau \
  --password "T3est123!!"

# Test both users and export results
./ad-auth-test --config config.test.yaml --username mtau --password "T3est123!!" --output admin_test.json
./ad-auth-test --config config.test.yaml --username bro --password "T3est1234!!" --output ro_test.json

# Verbose mode for debugging
./ad-auth-test --config config.test.yaml --username mtau --password "T3est123!!" --verbose

# Test specific group membership
./ad-auth-test --config config.test.yaml --username mtau --password "T3est123!!" --check-group "admin_users"
```

## Nice-to-Have Features
- Graceful shutdown handling
- Metrics endpoint (Prometheus format)
- Request ID tracking through headers
- API versioning support (/api/v1/...)
- OpenAPI/Swagger documentation generation with security scheme
- Group membership caching with TTL
- Nested group support (groups within groups)
- Dynamic group rule updates without restart
- Audit logging of all authorization decisions

## Deliverables
1. Complete source code with group-based authorization
2. Configuration file template with example group rules
3. **Test domain configuration file** (`config.test.yaml`) for mytestdomain.com
4. **AD authentication test utility** (`ad-auth-test`)
5. **Automated test suite** for mytestdomain.com with both test users
6. README.md with:
   - Setup instructions
   - Configuration guide
   - AD group configuration guide
   - Authorization rules documentation
   - Running instructions
   - API documentation
   - Testing examples including group-based access
   - **Test domain setup instructions**
   - **AD test utility usage guide**
7. Dockerfile
8. Example systemd service file
9. **Test report template** showing authentication and authorization results

## Non-Requirements
- Database integration (can be added later)
- Complex RBAC beyond AD group membership
- GUI/Admin panel
- Multi-tenancy
- Role hierarchy or permission inheritance beyond AD groups