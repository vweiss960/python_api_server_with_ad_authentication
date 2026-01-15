#!/usr/bin/env python3
"""
Standalone utility for testing Active Directory (LDAP) authentication.

Supports interactive and command-line modes for testing AD connectivity,
user authentication, and group memberships.

Usage:
    # Interactive mode
    python ad_auth_test.py

    # Command-line mode
    python ad_auth_test.py \\
      --server ldap://mytestdomain.com:389 \\
      --base-dn "DC=mytestdomain,DC=com" \\
      --username mtau \\
      --password "T3est123!!" \\
      --verbose

    # Test from config file
    python ad_auth_test.py \\
      --config ../config/config.test.yaml \\
      --username mtau \\
      --password "T3est123!!"
"""

import sys
import argparse
import getpass
import json
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any
import re

try:
    from ldap3 import Server, Connection, ALL
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback colors (ANSI codes)
    COLORAMA_AVAILABLE = False

    class Colors:
        GREEN = "\033[92m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        RESET = "\033[0m"

    Fore = Colors()

import os
from dotenv import load_dotenv


class ADAuthTestUtility:
    """Main utility class for AD authentication testing."""

    def __init__(self, verbose: bool = False):
        """
        Initialize utility.

        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.test_results: Dict[str, bool] = {}

    def print_header(self, text: str):
        """Print formatted header."""
        print(f"\n{Fore.BLUE}{'=' * 50}")
        print(f"{text}")
        print(f"{'=' * 50}{Fore.RESET}\n")

    def print_success(self, text: str):
        """Print success message with checkmark."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.GREEN}✓ {text}{Fore.RESET}")
        else:
            print(f"{Fore.GREEN}✓ {text}{Fore.RESET}")

    def print_error(self, text: str):
        """Print error message with X."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.RED}✗ {text}{Fore.RESET}")
        else:
            print(f"{Fore.RED}✗ {text}{Fore.RESET}")

    def print_warning(self, text: str):
        """Print warning message."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.YELLOW}⚠ {text}{Fore.RESET}")
        else:
            print(f"{Fore.YELLOW}⚠ {text}{Fore.RESET}")

    def print_info(self, text: str, indent: int = 0):
        """Print info message."""
        prefix = "  " * indent
        print(f"{prefix}{Fore.BLUE}→{Fore.RESET} {text}")

    def debug(self, text: str):
        """Print debug message if verbose mode enabled."""
        if self.verbose:
            print(f"{Fore.YELLOW}[DEBUG]{Fore.RESET} {text}")

    def _create_server(self, server_url: str) -> "Server":
        """
        Create ldap3 Server object from URL.

        Args:
            server_url: LDAP server URL (ldap://host:port or ldaps://host:port)

        Returns:
            ldap3 Server object
        """
        use_ssl = server_url.lower().startswith("ldaps://")
        host = server_url.replace("ldaps://", "").replace("ldap://", "")

        if ":" in host:
            host, port = host.rsplit(":", 1)
            port = int(port)
        else:
            port = 636 if use_ssl else 389

        return Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=10)

    def test_connectivity(self, server: str) -> bool:
        """
        Test connectivity to LDAP server.

        Args:
            server: LDAP server URL

        Returns:
            True if connection successful
        """
        print("\nTesting connectivity...", end=" ", flush=True)
        try:
            # Parse server URL
            server_obj = self._create_server(server)
            # Try to create a connection
            conn = Connection(server_obj, auto_bind=False)
            if conn.bind():
                conn.unbind()
                self.print_success("Connected to LDAP server")
                self.test_results["connectivity"] = True
                return True
            else:
                self.print_error(f"Cannot connect to LDAP server: {server}")
                self.test_results["connectivity"] = False
                return False
        except Exception as e:
            self.print_error(f"Connection failed: {str(e)}")
            self.test_results["connectivity"] = False
            return False

    def test_bind(self, server: str, bind_dn: str, bind_password: str) -> bool:
        """
        Test service account bind.

        Args:
            server: LDAP server URL
            bind_dn: Service account DN
            bind_password: Service account password

        Returns:
            True if bind successful
        """
        print("\nTesting service account bind...", end=" ", flush=True)
        try:
            server_obj = self._create_server(server)
            conn = Connection(server_obj, user=bind_dn, password=bind_password, auto_bind=False)
            if conn.bind():
                conn.unbind()
                self.print_success("Service account bind successful")
                self.test_results["bind"] = True
                return True
            else:
                self.print_error("Service account credentials invalid")
                self.test_results["bind"] = False
                return False
        except Exception as e:
            self.print_error(f"Bind failed: {str(e)}")
            self.test_results["bind"] = False
            return False

    def find_user(
        self,
        server: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        username: str,
    ) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Find user in LDAP directory.

        Args:
            server: LDAP server URL
            base_dn: Base DN for searches
            bind_dn: Service account DN
            bind_password: Service account password
            username: Username to search for

        Returns:
            Tuple of (user_dn, user_attributes) or (None, None) if not found
        """
        try:
            server_obj = self._create_server(server)
            conn = Connection(server_obj, user=bind_dn, password=bind_password, auto_bind=False)
            if not conn.bind():
                return None, None

            # Extract just the username part
            username_part = username.split("\\")[1] if "\\" in username else (username.split("@")[0] if "@" in username else username)

            # Search filters
            search_filters = [
                f"(sAMAccountName={username_part})",
                f"(userPrincipalName={username})",
            ]

            for search_filter in search_filters:
                try:
                    if conn.search(base_dn, search_filter, attributes=["*"]):
                        if conn.entries:
                            entry = conn.entries[0]
                            user_dn = entry.entry_dn
                            user_attrs = entry.entry_attributes_as_dict
                            conn.unbind()
                            self.debug(f"Found user: {user_dn}")
                            return user_dn, user_attrs
                except Exception as e:
                    self.debug(f"Search filter failed: {search_filter} - {str(e)}")
                    continue

            conn.unbind()
            return None, None

        except Exception as e:
            self.debug(f"Find user error: {str(e)}")
            return None, None

    def test_user_authentication(
        self,
        server: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        username: str,
        password: str,
    ) -> bool:
        """
        Test user authentication.

        Args:
            server: LDAP server URL
            base_dn: Base DN for searches
            bind_dn: Service account DN
            bind_password: Service account password
            username: Username to authenticate
            password: User password

        Returns:
            True if authentication successful
        """
        # Find user
        user_dn, user_attrs = self.find_user(server, base_dn, bind_dn, bind_password, username)
        if not user_dn:
            self.print_error(f"User not found: {username}")
            return False

        # Try to bind with user credentials
        try:
            server_obj = self._create_server(server)
            user_conn = Connection(server_obj, user=user_dn, password=password, auto_bind=False)
            if user_conn.bind():
                user_conn.unbind()
                self.print_success(f"Authentication successful for {username}")
                return True
            else:
                self.print_error(f"Authentication failed - invalid password for {username}")
                return False
        except Exception as e:
            self.print_error(f"Authentication error: {str(e)}")
            return False

    def get_user_groups(
        self,
        server: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        user_dn: str,
    ) -> List[str]:
        """
        Get user's group memberships.

        Args:
            server: LDAP server URL
            base_dn: Base DN for searches
            bind_dn: Service account DN
            bind_password: Service account password
            user_dn: User's distinguished name

        Returns:
            List of group DNs
        """
        try:
            server_obj = self._create_server(server)
            conn = Connection(server_obj, user=bind_dn, password=bind_password, auto_bind=False)
            if not conn.bind():
                return []

            # Search for groups where user is a member
            search_filter = f"(&(objectClass=group)(member={user_dn}))"
            if conn.search(base_dn, search_filter, attributes=["distinguishedName", "cn"]):
                groups = [entry.entry_dn for entry in conn.entries]
                conn.unbind()
                return groups

            conn.unbind()
            return []

        except Exception as e:
            self.debug(f"Get groups error: {str(e)}")
            return []

    def extract_cn_from_dn(self, dn: str) -> str:
        """Extract CN from distinguished name."""
        try:
            cn_part = dn.split(",")[0]
            if cn_part.startswith("CN="):
                return cn_part[3:]
        except:
            pass
        return dn

    def test_username_formats(
        self,
        server: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        username: str,
        password: str,
    ):
        """
        Test user authentication with multiple username formats.

        Args:
            server: LDAP server URL
            base_dn: Base DN
            bind_dn: Service account DN
            bind_password: Service account password
            username: Base username (sAMAccountName)
            password: User password
        """
        # Extract base username
        base_username = username.split("\\")[1] if "\\" in username else (username.split("@")[0] if "@" in username else username)

        # Infer domain from base_dn
        domain_parts = [x.split("=")[1] for x in base_dn.split(",") if x.startswith("DC=")]
        domain = ".".join(domain_parts) if domain_parts else "example.com"
        domain_short = domain_parts[0].upper() if domain_parts else "MTD"

        # Test different formats
        formats = [
            (base_username, "sAMAccountName"),
            (f"{domain_short}\\{base_username}", "Domain\\Username"),
            (f"{base_username}@{domain}", "UserPrincipalName"),
        ]

        print(f"\nTesting authentication with different username formats:")
        for fmt_username, fmt_name in formats:
            print(f"  Format: {fmt_name} ({fmt_username})...", end=" ", flush=True)
            if self.test_user_authentication(server, base_dn, bind_dn, bind_password, fmt_username, password):
                self.print_success("Success")
            else:
                self.print_error("Failed")

    def generate_report(self) -> Dict[str, Any]:
        """
        Generate test report.

        Returns:
            Report dictionary
        """
        all_passed = all(self.test_results.values())

        report = {
            "timestamp": str(__import__("datetime").datetime.utcnow()),
            "all_tests_passed": all_passed,
            "tests": self.test_results,
        }

        return report

    def run_interactive_mode(self):
        """Run interactive mode with prompts."""
        self.print_header("AD Authentication Test Utility")
        print("Interactive Mode - Enter your connection details")

        # Get connection details
        server = input("\nLDAP Server (e.g., ldap://ad.example.com:389): ").strip()
        base_dn = input("Base DN (e.g., DC=example,DC=com): ").strip()

        print("\n--- Service Account (optional, press Enter to skip) ---")
        bind_dn = input("Service Account DN: ").strip()

        if bind_dn:
            bind_password = getpass.getpass("Service Account Password: ")
            if self.test_connectivity(server):
                self.test_bind(server, bind_dn, bind_password)
        else:
            if self.test_connectivity(server):
                bind_dn = ""
                bind_password = ""

        # Get user credentials
        print("\n--- User Authentication ---")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        if not bind_dn:
            bind_dn = username
            bind_password = password

        # Test authentication
        print("\n\nTesting user authentication...")
        user_dn, user_attrs = self.find_user(server, base_dn, bind_dn, bind_password, username)

        if user_dn:
            self.print_success(f"User found: {user_dn}")

            # Display user attributes
            if user_attrs:
                print("\nUser Details:")
                display_name = self._get_attr(user_attrs, "displayName", "N/A")
                email = self._get_attr(user_attrs, "mail", "N/A")
                samaccountname = self._get_attr(user_attrs, "sAMAccountName", "N/A")

                self.print_info(f"Display Name: {display_name}", indent=1)
                self.print_info(f"Email: {email}", indent=1)
                self.print_info(f"sAMAccountName: {samaccountname}", indent=1)

            # Test different username formats
            if bind_password:
                self.test_username_formats(server, base_dn, bind_dn, bind_password, username, password)

            # Get groups
            groups = self.get_user_groups(server, base_dn, bind_dn, bind_password, user_dn)
            if groups:
                print(f"\nGroup Memberships ({len(groups)}):")
                for group_dn in groups:
                    group_cn = self.extract_cn_from_dn(group_dn)
                    self.print_success(f"{group_dn}", )

            # Test authentication
            if self.test_user_authentication(server, base_dn, bind_dn, bind_password, username, password):
                self.test_results["authentication"] = True
            else:
                self.test_results["authentication"] = False

        else:
            self.print_error(f"User not found: {username}")

        # Print summary
        print("\n")
        self.print_header("Test Summary")
        if all(self.test_results.values()):
            self.print_success("All tests passed!")
        else:
            self.print_warning("Some tests failed")
            for test_name, result in self.test_results.items():
                status = "PASS" if result else "FAIL"
                symbol = "✓" if result else "✗"
                print(f"  {symbol} {test_name.upper()}: {status}")

    def run_command_line_mode(
        self,
        server: str,
        base_dn: str,
        username: str,
        password: str,
        bind_dn: Optional[str] = None,
        bind_password: Optional[str] = None,
        test_bind_flag: bool = False,
        check_group: Optional[str] = None,
        output: Optional[str] = None,
    ):
        """
        Run command-line mode with provided arguments.

        Args:
            server: LDAP server URL
            base_dn: Base DN
            username: Username
            password: Password
            bind_dn: Service account DN
            bind_password: Service account password
            test_bind_flag: Test bind only
            check_group: Check if user is in specific group
            output: Output file for JSON report
        """
        self.print_header("AD Authentication Test Utility")

        print(f"Connection Details:")
        self.print_info(f"Server: {server}", indent=1)
        self.print_info(f"Base DN: {base_dn}", indent=1)
        self.print_info(f"Use SSL: No", indent=1)

        # Test connectivity
        if not self.test_connectivity(server):
            return

        # Test bind if requested
        if test_bind_flag and bind_dn and bind_password:
            if not self.test_bind(server, bind_dn, bind_password):
                return

        # If no user provided, exit
        if not username:
            print("\n✓ Connection test completed")
            return

        # Find user
        actual_bind_dn = bind_dn or username
        actual_bind_password = bind_password or password

        user_dn, user_attrs = self.find_user(server, base_dn, actual_bind_dn, actual_bind_password, username)

        if not user_dn:
            self.print_error(f"User not found: {username}")
            return

        self.print_success(f"User found: {user_dn}")

        # Display user attributes
        if user_attrs:
            print("\nUser Details:")
            display_name = self._get_attr(user_attrs, "displayName", "N/A")
            email = self._get_attr(user_attrs, "mail", "N/A")
            samaccountname = self._get_attr(user_attrs, "sAMAccountName", "N/A")

            self.print_info(f"DN: {user_dn}", indent=1)
            self.print_info(f"Display Name: {display_name}", indent=1)
            self.print_info(f"Email: {email}", indent=1)
            self.print_info(f"sAMAccountName: {samaccountname}", indent=1)

        # Test authentication
        if self.test_user_authentication(server, base_dn, actual_bind_dn, actual_bind_password, username, password):
            self.test_results["authentication"] = True
        else:
            self.test_results["authentication"] = False
            return

        # Get groups
        groups = self.get_user_groups(server, base_dn, actual_bind_dn, actual_bind_password, user_dn)
        if groups:
            print(f"\nGroup Memberships ({len(groups)}):")
            for group_dn in groups:
                group_cn = self.extract_cn_from_dn(group_dn)
                self.print_success(f"{group_cn}", )
                if self.verbose:
                    self.print_info(f"DN: {group_dn}", indent=2)

            # Check specific group if requested
            if check_group:
                print(f"\nChecking group membership: {check_group}")
                group_names = [self.extract_cn_from_dn(g) for g in groups]
                if check_group in group_names:
                    self.print_success(f"User is member of {check_group}")
                else:
                    self.print_error(f"User is NOT member of {check_group}")

        # Output report
        if output:
            report = self.generate_report()
            with open(output, "w") as f:
                json.dump(report, f, indent=2)
            self.print_success(f"Report saved to {output}")

    def _get_attr(self, attrs: Dict, key: str, default: str = "") -> str:
        """Extract attribute value from LDAP attributes dictionary."""
        if key in attrs and attrs[key]:
            val = attrs[key][0]
            return val.decode("utf-8") if isinstance(val, bytes) else val
        return default


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    if not YAML_AVAILABLE:
        print("Error: PyYAML required to load config files", file=sys.stderr)
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {config_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to load configuration: {str(e)}", file=sys.stderr)
        sys.exit(1)


def resolve_env_var(value: str) -> str:
    """Resolve environment variable reference."""
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        var_name = value[2:-1]
        import os
        env_value = os.environ.get(var_name)
        if env_value is None:
            raise ValueError(f"Environment variable not set: {var_name}")
        return env_value
    return value


def main():
    """Main entry point."""
    # Load environment variables from .env file if it exists
    env_file = Path(__file__).parent.parent / ".env"
    if env_file.exists():
        load_dotenv(env_file)

    # Check dependencies
    if not LDAP_AVAILABLE:
        print("Error: ldap3 required. Install with: pip install ldap3", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Active Directory (LDAP) Authentication Test Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python ad_auth_test.py

  # Command-line mode with all parameters
  python ad_auth_test.py \\
    --server ldap://mytestdomain.com:389 \\
    --base-dn "DC=mytestdomain,DC=com" \\
    --username mtau \\
    --password "T3est123!!" \\
    --verbose

  # Load from config file
  python ad_auth_test.py --config config.yaml --username mtau --password "T3est123!!"

  # Check specific group membership
  python ad_auth_test.py --config config.yaml --username mtau --password "T3est123!!" \\
    --check-group "admin_users"

  # Save results to file
  python ad_auth_test.py --config config.yaml --username mtau --password "T3est123!!" \\
    --output test_result.json
        """,
    )

    parser.add_argument("--server", help="LDAP server URL (e.g., ldap://ad.example.com:389)")
    parser.add_argument("--base-dn", help="Base DN for searches (e.g., DC=example,DC=com)")
    parser.add_argument("--username", help="Username to authenticate")
    parser.add_argument("--password", help="User password")
    parser.add_argument("--bind-dn", help="Service account DN (optional)")
    parser.add_argument("--bind-password", help="Service account password (optional)")
    parser.add_argument("--config", help="Configuration file path (YAML format)")
    parser.add_argument("--test-bind", action="store_true", help="Test service account bind only")
    parser.add_argument("--check-group", help="Check if user is in specified group")
    parser.add_argument("--output", help="Output JSON report to file")
    parser.add_argument("--verbose", action="store_true", help="Verbose mode with debug output")

    args = parser.parse_args()

    # Initialize utility
    utility = ADAuthTestUtility(verbose=args.verbose)

    # Load from config if provided
    if args.config:
        config = load_config(args.config)
        ad_config = config.get("ad", {})

        server = args.server or ad_config.get("server")
        base_dn = args.base_dn or ad_config.get("base_dn")
        bind_dn = args.bind_dn or ad_config.get("bind_dn")
        bind_password = args.bind_password or ad_config.get("bind_password", "")

        # Resolve environment variables
        try:
            if bind_password:
                bind_password = resolve_env_var(bind_password)
        except ValueError as e:
            print(f"Error: {str(e)}", file=sys.stderr)
            sys.exit(1)

    else:
        server = args.server
        base_dn = args.base_dn
        bind_dn = args.bind_dn
        bind_password = args.bind_password

    username = args.username
    password = args.password

    # If no arguments provided, use interactive mode
    if not server or not base_dn:
        utility.run_interactive_mode()
    else:
        # Command-line mode
        if args.test_bind and not username:
            # Test bind mode
            utility.run_command_line_mode(
                server=server,
                base_dn=base_dn,
                username="",
                password="",
                bind_dn=bind_dn,
                bind_password=bind_password,
                test_bind_flag=True,
                output=args.output,
            )
        elif username and password:
            # Full test mode
            utility.run_command_line_mode(
                server=server,
                base_dn=base_dn,
                username=username,
                password=password,
                bind_dn=bind_dn,
                bind_password=bind_password,
                test_bind_flag=args.test_bind,
                check_group=args.check_group,
                output=args.output,
            )
        else:
            print("Error: Either provide --server and --base-dn for interactive mode,", file=sys.stderr)
            print("       or --username and --password for command-line mode", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
