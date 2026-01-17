#!/usr/bin/env python3
"""
Comprehensive API endpoint test suite for AD authentication and authorization.

Tests all endpoints with different user groups to verify:
- Authentication (login, token validation)
- Group-based authorization
- Public endpoint access
- Protected endpoint access
- Authorization failures

Test users from .env:
- TEST_ADMIN_USER: admin_users group (full access)
- TEST_RO_USER: ro_users group (read-only access)

Run with: python tests/test_api_endpoints.py
"""

import os
import sys
import json
import time
import subprocess
import ssl
from pathlib import Path
from typing import Dict, Tuple, Optional
from dotenv import load_dotenv

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.ssl_ import create_urllib3_context
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Error: requests library required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)


class InsecureHTTPSAdapter(HTTPAdapter):
    """HTTPS adapter that trusts all certificates (for testing only)."""

    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with insecure SSL context."""
        context = create_urllib3_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)


class APITestSuite:
    """Test suite for API endpoint authentication and authorization."""

    def __init__(self, base_url: str = "http://localhost:8443", use_https: bool = False):
        """Initialize test suite."""
        self.base_url = base_url
        self.use_https = use_https
        self.admin_token = None
        self.ro_token = None
        self.test_results: Dict[str, bool] = {}
        self.server_process = None
        self._setup_requests_session()

    def _setup_requests_session(self):
        """Setup requests session with appropriate SSL settings."""
        self.session = requests.Session()
        if self.use_https:
            # Use insecure HTTPS adapter for testing with self-signed certs
            adapter = InsecureHTTPSAdapter()
            self.session.mount("https://", adapter)

    def print_header(self, text: str):
        """Print formatted header."""
        print(f"\n{'=' * 70}")
        print(f"  {text}")
        print(f"{'=' * 70}\n")

    def print_test(self, name: str, passed: bool):
        """Print test result."""
        status = "[PASS]" if passed else "[FAIL]"
        self.test_results[name] = passed
        print(f"{status}: {name}")

    def check_server_running(self) -> bool:
        """Check if API server is running."""
        try:
            # Use verify=False for self-signed certificates
            response = self.session.get(f"{self.base_url}/health", timeout=2, verify=False)
            return response.status_code == 200
        except Exception as e:
            return False

    def _kill_process_on_port(self, port: int) -> bool:
        """Kill any process running on the specified port."""
        try:
            # Try fuser first (Linux/Unix)
            import subprocess
            try:
                result = subprocess.run(
                    ["fuser", f"{port}/tcp"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    # Get the PID from fuser output
                    pid = result.stdout.strip()
                    if pid:
                        subprocess.run(["kill", "-9", pid], timeout=5)
                        time.sleep(1)
                        return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                # fuser not available, try lsof
                pass

            # Fallback to lsof
            try:
                result = subprocess.run(
                    ["lsof", "-ti", f":{port}"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    pid = result.stdout.strip().split('\n')[0]
                    if pid:
                        subprocess.run(["kill", "-9", pid], timeout=5)
                        time.sleep(1)
                        return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            return False
        except Exception as e:
            print(f"[WARNING] Could not kill process on port {port}: {str(e)}")
            return False

    def start_server(self) -> bool:
        """Start API server if not running."""
        if self.check_server_running():
            print("[INFO] API server is already running")
            return True

        print("[INFO] Starting API server...")
        try:
            # Kill any existing process on port 8443 to avoid conflicts
            self._kill_process_on_port(8443)
            time.sleep(0.5)  # Give OS time to release the port

            # Get project root
            project_root = Path(__file__).parent.parent
            env_file = project_root / ".env"

            # Start server with environment variables
            env = os.environ.copy()
            if env_file.exists():
                load_dotenv(env_file)
                env.update(os.environ)

            # Create log file for server output
            log_file = project_root / "test_server.log"

            with open(log_file, 'w') as log:
                # Use Windows-specific flags to detach process
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

                self.server_process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "src.main",
                        "--config",
                        str(project_root / "config" / "config.test.yaml"),
                    ],
                    cwd=str(project_root),
                    env=env,
                    stdout=log,
                    stderr=log,
                    creationflags=creationflags,
                )

            # Wait for server to start
            for _ in range(30):
                time.sleep(0.5)
                if self.check_server_running():
                    print("[INFO] API server started successfully")
                    return True

            print("[ERROR] Server failed to start after 15 seconds")
            # Print server log for debugging
            try:
                with open(log_file, 'r') as f:
                    log_content = f.read()
                    if log_content:
                        print("[SERVER LOG]")
                        print(log_content)
            except Exception:
                pass
            return False

        except Exception as e:
            print(f"[ERROR] Failed to start server: {str(e)}")
            return False

    def stop_server(self):
        """Stop API server gracefully."""
        if self.server_process:
            print("[INFO] Stopping API server...")
            try:
                # Attempt graceful termination
                self.server_process.terminate()
                try:
                    self.server_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful termination fails
                    self.server_process.kill()
                    self.server_process.wait()
            except Exception as e:
                print(f"[WARNING] Error stopping server: {str(e)}")

    def login_user(self, username: str, password: str) -> Optional[str]:
        """Login user and return JWT token."""
        try:
            response = self.session.post(
                f"{self.base_url}/auth/login",
                json={"username": username, "password": password},
            )
            if response.status_code == 200:
                return response.json().get("token")
            else:
                print(f"    Login failed with status {response.status_code}: {response.text}")
            return None
        except Exception as e:
            print(f"    Login request error: {str(e)}")
            return None

    def make_request(
        self,
        method: str,
        endpoint: str,
        token: Optional[str] = None,
        expected_status: int = 200,
    ) -> Tuple[bool, int]:
        """Make HTTP request to endpoint."""
        try:
            url = f"{self.base_url}{endpoint}"
            headers = {}
            if token:
                headers["Authorization"] = f"Bearer {token}"

            if method == "GET":
                response = self.session.get(url, headers=headers, timeout=5)
            elif method == "POST":
                response = self.session.post(url, headers=headers, timeout=5)
            else:
                return False, 0

            return response.status_code == expected_status, response.status_code

        except Exception as e:
            print(f"    Request error: {str(e)}")
            return False, 0

    def test_public_endpoints(self):
        """Test endpoints that don't require authentication."""
        self.print_header("Testing Public Endpoints")

        # Health check
        passed, _ = self.make_request("GET", "/health", expected_status=200)
        self.print_test("GET /health (no auth required)", passed)

    def test_login_endpoints(self):
        """Test login endpoint with different users."""
        self.print_header("Testing Authentication/Login")

        # Admin user login
        self.admin_token = self.login_user(
            os.getenv("TEST_ADMIN_USER", "MTD\\mtau"),
            os.getenv("TEST_ADMIN_PASSWORD", "T3est123!!"),
        )
        admin_passed = self.admin_token is not None
        self.print_test("POST /auth/login (admin user)", admin_passed)

        # Read-only user login
        self.ro_token = self.login_user(
            os.getenv("TEST_RO_USER", "MTD\\bro"),
            os.getenv("TEST_RO_PASSWORD", "T3est1234!!"),
        )
        ro_passed = self.ro_token is not None
        self.print_test("POST /auth/login (ro user)", ro_passed)

        # Invalid credentials
        invalid_token = self.login_user("invalid_user", "wrong_password")
        invalid_passed = invalid_token is None
        self.print_test("POST /auth/login (invalid credentials - should fail)", invalid_passed)

    def test_user_info_endpoints(self):
        """Test user info endpoints (auth required, no group restrictions)."""
        self.print_header("Testing User Info Endpoints")

        if not self.admin_token:
            print("[SKIP] Admin token not available")
            return

        # Get user info
        passed, _ = self.make_request("GET", "/api/user/info", self.admin_token, 200)
        self.print_test("GET /api/user/info (admin user)", passed)

        # Get user groups
        passed, _ = self.make_request("GET", "/api/user/groups", self.admin_token, 200)
        self.print_test("GET /api/user/groups (admin user)", passed)

        # Test with ro user
        if self.ro_token:
            passed, _ = self.make_request("GET", "/api/user/info", self.ro_token, 200)
            self.print_test("GET /api/user/info (ro user)", passed)

    def test_data_read_endpoints(self):
        """Test data read endpoints (requires Data-Readers OR Data-Writers group)."""
        self.print_header("Testing Data Read Endpoints")

        if not self.admin_token or not self.ro_token:
            print("[SKIP] Required tokens not available")
            return

        # Admin user can read (has admin_users which has read access)
        passed, _ = self.make_request("GET", "/api/data/read", self.admin_token, 200)
        self.print_test("GET /api/data/read (admin user - should pass)", passed)

        # RO user can read (has ro_users which has read access)
        passed, _ = self.make_request("GET", "/api/data/read", self.ro_token, 200)
        self.print_test("GET /api/data/read (ro user - should pass)", passed)

        # No token should fail
        passed, status = self.make_request("GET", "/api/data/read", None, 401)
        self.print_test("GET /api/data/read (no token - should return 401)", passed)

    def test_data_write_endpoints(self):
        """Test data write endpoints (requires Data-Writers group)."""
        self.print_header("Testing Data Write Endpoints")

        if not self.admin_token or not self.ro_token:
            print("[SKIP] Required tokens not available")
            return

        # Admin user can write (has admin_users which has write access)
        passed, _ = self.make_request("POST", "/api/data/write", self.admin_token, 200)
        self.print_test("POST /api/data/write (admin user - should pass)", passed)

        # RO user cannot write (ro_users group doesn't have write access)
        passed, status = self.make_request("POST", "/api/data/write", self.ro_token, 403)
        self.print_test("POST /api/data/write (ro user - should return 403)", passed)

        # No token should fail
        passed, status = self.make_request("POST", "/api/data/write", None, 401)
        self.print_test("POST /api/data/write (no token - should return 401)", passed)

    def test_admin_endpoints(self):
        """Test admin endpoints (requires API-Admins group)."""
        self.print_header("Testing Admin Endpoints")

        if not self.admin_token or not self.ro_token:
            print("[SKIP] Required tokens not available")
            return

        # Admin user can access admin endpoints (has admin_users group)
        passed, _ = self.make_request("GET", "/api/admin/users", self.admin_token, 200)
        self.print_test("GET /api/admin/users (admin user - should pass)", passed)

        # RO user cannot access admin endpoints (ro_users group doesn't have admin access)
        passed, status = self.make_request("GET", "/api/admin/users", self.ro_token, 403)
        self.print_test("GET /api/admin/users (ro user - should return 403)", passed)

        # Admin can get settings
        passed, _ = self.make_request("GET", "/api/admin/settings", self.admin_token, 200)
        self.print_test("GET /api/admin/settings (admin user - should pass)", passed)

        # Admin can view rules
        passed, _ = self.make_request("GET", "/api/admin/rules", self.admin_token, 200)
        self.print_test("GET /api/admin/rules (admin user - should pass)", passed)

        # No token should fail
        passed, status = self.make_request("GET", "/api/admin/users", None, 401)
        self.print_test("GET /api/admin/users (no token - should return 401)", passed)

    def test_authorization_check_endpoint(self):
        """Test the check-access endpoint."""
        self.print_header("Testing Authorization Check Endpoint")

        if not self.admin_token:
            print("[SKIP] Admin token not available")
            return

        try:
            # Check access to admin endpoint
            response = self.session.post(
                f"{self.base_url}/api/admin/check-access",
                json={"path": "/api/admin/users"},
                headers={"Authorization": f"Bearer {self.admin_token}"},
            )
            passed = response.status_code == 200
            self.print_test("POST /api/admin/check-access (admin user to /api/admin/users)", passed)
        except Exception:
            self.print_test("POST /api/admin/check-access (admin user to /api/admin/users)", False)

    def test_ldap_secure_connection(self):
        """Test that LDAP connection uses TLS with CA certificate validation."""
        self.print_header("Testing Secure LDAP Connection")

        try:
            # Add project root to path to enable imports
            import sys
            project_root = Path(__file__).parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))

            # Import the authenticator to check configuration
            from src.security.auth import LDAPAuthenticator
            from src.config import ConfigLoader

            # Load the test config
            project_root = Path(__file__).parent.parent
            config_path = project_root / "config" / "config.test.yaml"

            loader = ConfigLoader(str(config_path))
            config = loader.get()

            # Verify LDAP configuration
            ldap_config = config.ad

            # Check that use_ssl is enabled
            use_ssl_passed = ldap_config.use_ssl is True
            self.print_test("LDAP use_ssl is enabled", use_ssl_passed)

            # Check that ca_certs_file is specified
            ca_certs_passed = ldap_config.ca_certs_file is not None
            self.print_test("LDAP ca_certs_file is specified", ca_certs_passed)

            # Check that the CA cert file exists
            if ldap_config.ca_certs_file:
                ca_file_path = Path(ldap_config.ca_certs_file)
                ca_file_exists = ca_file_path.exists()
                self.print_test(
                    f"LDAP CA certificate file exists ({ldap_config.ca_certs_file})",
                    ca_file_exists,
                )
            else:
                self.print_test("LDAP CA certificate file path specified", False)

            # Check that server uses ldaps protocol
            ldaps_protocol = ldap_config.server.lower().startswith("ldaps://")
            self.print_test(
                f"LDAP server uses secure protocol (ldaps://) - {ldap_config.server}",
                ldaps_protocol,
            )

            # Verify the authenticator creates TLS configuration
            try:
                authenticator = LDAPAuthenticator(ldap_config)
                server = authenticator._get_server()

                # Check if TLS is configured on the server object
                tls_configured = server.tls is not None
                self.print_test("LDAPAuthenticator creates TLS configuration", tls_configured)

                if tls_configured:
                    # Verify TLS validation is required
                    import ssl as ssl_module

                    tls_validate_required = server.tls.validate == ssl_module.CERT_REQUIRED
                    self.print_test("TLS certificate validation is REQUIRED", tls_validate_required)

            except Exception as e:
                self.print_test(
                    f"LDAPAuthenticator TLS configuration verification",
                    False,
                )
                print(f"    Error: {str(e)}")

        except Exception as e:
            self.print_test("Secure LDAP connection configuration check", False)
            print(f"    Error: {str(e)}")

    def test_api_ssl_encryption(self):
        """Test that API server uses SSL/TLS encryption."""
        self.print_header("Testing API Server SSL/TLS Encryption")

        if not self.use_https:
            print("[SKIP] Test suite not configured for HTTPS (use_https=True)")
            return

        try:
            # Add project root to path to enable imports
            import sys
            project_root = Path(__file__).parent.parent
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))

            from src.config import ConfigLoader

            # Load the test config
            project_root = Path(__file__).parent.parent
            config_path = project_root / "config" / "config.test.yaml"

            loader = ConfigLoader(str(config_path))
            config = loader.get()

            # Verify server TLS configuration
            server_config = config.server

            # Check that TLS is enabled
            tls_enabled = server_config.tls_enabled is True
            self.print_test("Server TLS is enabled", tls_enabled)

            # Check that certificate file is specified
            cert_file_passed = server_config.cert_file is not None
            self.print_test("Server certificate file is specified", cert_file_passed)

            # Check that certificate file exists
            if server_config.cert_file:
                cert_path = Path(server_config.cert_file)
                cert_exists = cert_path.exists()
                self.print_test(
                    f"Server certificate file exists ({server_config.cert_file})",
                    cert_exists,
                )
            else:
                self.print_test("Server certificate file exists", False)

            # Check that key file is specified
            key_file_passed = server_config.key_file is not None
            self.print_test("Server key file is specified", key_file_passed)

            # Check that key file exists
            if server_config.key_file:
                key_path = Path(server_config.key_file)
                key_exists = key_path.exists()
                self.print_test(
                    f"Server key file exists ({server_config.key_file})",
                    key_exists,
                )
            else:
                self.print_test("Server key file exists", False)

            # Test that we can establish HTTPS connection with cert trust disabled
            try:
                response = self.session.get(f"{self.base_url}/health", timeout=5)
                connection_passed = response.status_code == 200
                self.print_test(
                    "HTTPS connection successful (with certificate trust disabled for testing)",
                    connection_passed,
                )
            except Exception as e:
                self.print_test(
                    "HTTPS connection successful (with certificate trust disabled for testing)",
                    False,
                )
                print(f"    Error: {str(e)}")

        except Exception as e:
            self.print_test("API server SSL/TLS encryption configuration check", False)
            print(f"    Error: {str(e)}")

    def test_invalid_token(self):
        """Test endpoints with invalid tokens."""
        self.print_header("Testing Invalid Token Handling")

        invalid_token = "invalid.token.here"

        # Should return 401 for invalid token
        passed, status = self.make_request("GET", "/api/user/info", invalid_token, 401)
        self.print_test("GET /api/user/info (invalid token - should return 401)", passed)

    def print_summary(self):
        """Print test summary."""
        self.print_header("Test Summary")

        total = len(self.test_results)
        passed = sum(1 for v in self.test_results.values() if v)
        failed = total - passed

        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")

        if failed > 0:
            print("\nFailed Tests:")
            for name, result in self.test_results.items():
                if not result:
                    print(f"  - {name}")

        print()
        return failed == 0

    def run_all_tests(self) -> bool:
        """Run all tests."""
        try:
            # Start server
            if not self.start_server():
                print("\n[ERROR] Cannot start API server. Please check configuration.")
                return False

            # Run test suites
            self.test_public_endpoints()
            self.test_login_endpoints()
            self.test_user_info_endpoints()
            self.test_data_read_endpoints()
            self.test_data_write_endpoints()
            self.test_admin_endpoints()
            self.test_authorization_check_endpoint()
            self.test_ldap_secure_connection()
            self.test_api_ssl_encryption()
            self.test_invalid_token()

            # Print summary
            all_passed = self.print_summary()
            return all_passed

        finally:
            # Cleanup
            self.stop_server()


def main():
    """Main entry point."""
    # Setup Python path to ensure src module can be imported
    project_root = Path(__file__).parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    # Load environment variables
    env_file = project_root / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    else:
        print("[WARNING] .env file not found. Using default test credentials.")

    # Check for HTTPS flag or auto-detect from config
    use_https = "--https" in sys.argv or "HTTPS" in os.environ

    # Auto-detect TLS from config if not explicitly set
    if not use_https:
        try:
            from src.config import ConfigLoader
            config_path = project_root / "config" / "config.test.yaml"
            loader = ConfigLoader(str(config_path))
            config = loader.get()
            use_https = config.server.tls_enabled
        except Exception as e:
            print(f"[DEBUG] Could not auto-detect TLS from config: {str(e)}")
            pass  # Fall back to manual flag if config loading fails

    base_url = "https://localhost:8443" if use_https else "http://localhost:8443"

    print("\n" + "=" * 70)
    print("  API Endpoint Test Suite")
    print("  Testing AD Authentication and Group-Based Authorization")
    if use_https:
        print("  Protocol: HTTPS (with self-signed certificate trust)")
    else:
        print("  Protocol: HTTP")
    print("=" * 70)

    # Create test suite
    suite = APITestSuite(base_url=base_url, use_https=use_https)

    # Run tests
    all_passed = suite.run_all_tests()

    # Exit with appropriate code
    if not all_passed:
        print("\n[WARNING] Some tests failed. Please review the results above.")
        sys.exit(1)

    print("\n[SUCCESS] All tests passed!")
    sys.exit(0)


if __name__ == "__main__":
    main()
