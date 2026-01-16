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
from pathlib import Path
from typing import Dict, Tuple, Optional
from dotenv import load_dotenv

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Error: requests library required. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)


class APITestSuite:
    """Test suite for API endpoint authentication and authorization."""

    def __init__(self, base_url: str = "http://localhost:8443"):
        """Initialize test suite."""
        self.base_url = base_url
        self.admin_token = None
        self.ro_token = None
        self.test_results: Dict[str, bool] = {}
        self.server_process = None

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
            response = requests.get(f"{self.base_url}/health", timeout=2, verify=False)
            return response.status_code == 200
        except Exception:
            return False

    def start_server(self) -> bool:
        """Start API server if not running."""
        if self.check_server_running():
            print("[INFO] API server is already running")
            return True

        print("[INFO] Starting API server...")
        try:
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
            response = requests.post(
                f"{self.base_url}/auth/login",
                json={"username": username, "password": password},
                verify=False,
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
                response = requests.get(url, headers=headers, verify=False, timeout=5)
            elif method == "POST":
                response = requests.post(url, headers=headers, verify=False, timeout=5)
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
            response = requests.post(
                f"{self.base_url}/api/admin/check-access",
                json={"path": "/api/admin/users"},
                headers={"Authorization": f"Bearer {self.admin_token}"},
                verify=False,
            )
            passed = response.status_code == 200
            self.print_test("POST /api/admin/check-access (admin user to /api/admin/users)", passed)
        except Exception:
            self.print_test("POST /api/admin/check-access (admin user to /api/admin/users)", False)

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
            self.test_invalid_token()

            # Print summary
            all_passed = self.print_summary()
            return all_passed

        finally:
            # Cleanup
            self.stop_server()


def main():
    """Main entry point."""
    # Load environment variables
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)
    else:
        print("[WARNING] .env file not found. Using default test credentials.")

    print("\n" + "=" * 70)
    print("  API Endpoint Test Suite")
    print("  Testing AD Authentication and Group-Based Authorization")
    print("=" * 70)

    # Create test suite
    suite = APITestSuite()

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
