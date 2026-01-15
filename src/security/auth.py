"""
Active Directory (LDAP) authentication module using ldap3.

Uses the pure Python ldap3 library which works cross-platform without
requiring compiled C extensions.
"""

from ldap3 import Server, Connection, ALL, NTLM
from ldap3.core.exceptions import LDAPException, LDAPInvalidCredentialsResult
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass

from src.config import ADConfig
from src.utils.logger import get_logger
from src.utils.errors import (
    InvalidCredentialsError,
    ADConnectionError,
)

logger = get_logger("auth")


@dataclass
class UserInfo:
    """User information retrieved from AD."""
    username: str
    dn: str
    display_name: Optional[str] = None
    email: Optional[str] = None
    groups: List[str] = None

    def __post_init__(self):
        if self.groups is None:
            self.groups = []


class LDAPAuthenticator:
    """Handles authentication against LDAP/Active Directory using ldap3."""

    def __init__(self, config: ADConfig):
        """
        Initialize LDAP authenticator.

        Args:
            config: Active Directory configuration
        """
        self.config = config
        self._server = None
        self._conn = None

    def _get_server(self) -> Server:
        """
        Get or create LDAP server object.

        Returns:
            ldap3 Server object
        """
        if self._server is None:
            try:
                # Parse server URL to extract host and port
                server_url = self.config.server
                use_ssl = server_url.lower().startswith("ldaps://")

                # Remove protocol prefix
                host = server_url.replace("ldaps://", "").replace("ldap://", "")

                # Split host and port
                if ":" in host:
                    host, port = host.rsplit(":", 1)
                    port = int(port)
                else:
                    port = 636 if use_ssl else 389

                logger.debug(f"Connecting to LDAP server: {host}:{port} (SSL: {use_ssl})")

                self._server = Server(
                    host,
                    port=port,
                    use_ssl=use_ssl,
                    get_info=ALL,
                    connect_timeout=self.config.timeout,
                )
            except Exception as e:
                raise ADConnectionError(f"Failed to create server object: {str(e)}")

        return self._server

    def _get_connection(self) -> Connection:
        """
        Get or create LDAP connection.

        Returns:
            ldap3 Connection object

        Raises:
            ADConnectionError: If connection fails
        """
        if self._conn is None:
            try:
                server = self._get_server()
                self._conn = Connection(
                    server,
                    user=self.config.bind_dn,
                    password=self.config.bind_password,
                    auto_bind=False,
                )

                # Perform the bind
                if not self._conn.bind():
                    raise ADConnectionError("Failed to bind with service account credentials")

                logger.info("Successfully connected to AD server")
            except LDAPInvalidCredentialsResult:
                self._conn = None
                raise ADConnectionError("Invalid service account credentials for AD bind")
            except Exception as e:
                self._conn = None
                raise ADConnectionError(f"Failed to connect to AD: {str(e)}")

        return self._conn

    def close(self):
        """Close LDAP connection."""
        if self._conn:
            try:
                self._conn.unbind()
            except:
                pass
            self._conn = None

    def _normalize_username(self, username: str) -> str:
        r"""
        Normalize username to sAMAccountName format.

        Handles multiple formats:
        - sAMAccountName: just the name
        - Domain\Username: extract the username part
        - UserPrincipalName: extract the name part before @

        Args:
            username: Username in any supported format

        Returns:
            Normalized username
        """
        if "\\" in username:
            # Domain\Username format
            return username.split("\\")[1]
        elif "@" in username:
            # UserPrincipalName format
            return username.split("@")[0]
        return username

    def _find_user(self, username: str) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Find user in LDAP directory.

        Args:
            username: Username in any supported format

        Returns:
            Tuple of (user_dn, user_attributes) or (None, None) if not found

        Raises:
            ADConnectionError: If LDAP connection fails
        """
        try:
            conn = self._get_connection()
            normalized_username = self._normalize_username(username)

            # Build the search filter using the configured template
            filter_template = self.config.user_search_filter
            search_filter = filter_template.format(username=normalized_username)

            logger.debug(f"Searching for user with filter: {search_filter}")

            # Perform the search
            if not conn.search(
                search_base=self.config.base_dn,
                search_filter=search_filter,
                attributes=["*"],
            ):
                logger.warning(f"User not found: {username}")
                return None, None

            # Get the first result
            if conn.entries:
                entry = conn.entries[0]
                user_dn = entry.entry_dn
                user_attrs = entry.entry_attributes_as_dict

                logger.debug(f"Found user: {user_dn}")
                return user_dn, user_attrs

            return None, None

        except Exception as e:
            logger.error(f"Error searching for user {username}: {str(e)}")
            raise ADConnectionError(f"User search failed: {str(e)}")

    def _get_user_groups(self, user_dn: str) -> List[str]:
        """
        Get user's group memberships from AD.

        Args:
            user_dn: Distinguished name of the user

        Returns:
            List of group DNs

        Raises:
            ADConnectionError: If LDAP connection fails
        """
        try:
            conn = self._get_connection()
            groups = []

            # Search for groups where user is a member
            search_filter = self.config.group_search_filter.format(user_dn=user_dn)
            group_base = self.config.group_base_dn or self.config.base_dn

            logger.debug(f"Searching for groups with filter: {search_filter}")

            if not conn.search(
                search_base=group_base,
                search_filter=search_filter,
                attributes=["distinguishedName", "cn"],
            ):
                logger.debug(f"No groups found for user {user_dn}")
                return groups

            # Extract group DNs from results
            for entry in conn.entries:
                group_dn = entry.entry_dn
                groups.append(group_dn)
                logger.debug(f"Found group for user: {group_dn}")

            logger.info(f"User {user_dn} has {len(groups)} group memberships")
            return groups

        except Exception as e:
            logger.error(f"Failed to retrieve groups for user {user_dn}: {str(e)}")
            # Don't raise error, just return empty list
            return []

    def _extract_user_attributes(self, attributes: Dict) -> Dict[str, str]:
        """
        Extract useful user attributes from LDAP attributes.

        Args:
            attributes: LDAP attributes dictionary

        Returns:
            Dictionary with extracted attributes
        """
        extracted = {}

        # Helper to safely get attribute value
        def get_attr(key: str, default: str = "") -> str:
            if key in attributes and attributes[key]:
                val = attributes[key]
                # ldap3 returns lists of values
                if isinstance(val, list) and val:
                    val = val[0]
                return val.decode("utf-8") if isinstance(val, bytes) else str(val)
            return default

        extracted["display_name"] = get_attr("displayName")
        extracted["email"] = get_attr("mail")
        extracted["samaccountname"] = get_attr("sAMAccountName")

        return extracted

    def authenticate(self, username: str, password: str) -> UserInfo:
        r"""
        Authenticate user against AD.

        Args:
            username: Username (supports sAMAccountName, Domain\Username, or UPN format)
            password: User password

        Returns:
            UserInfo object with user details and group memberships

        Raises:
            InvalidCredentialsError: If credentials are invalid
            ADConnectionError: If AD connection fails
        """
        if not username or not password:
            logger.warning("Authentication attempt with empty credentials")
            raise InvalidCredentialsError("Username and password required")

        logger.info(f"Authenticating user: {username}")

        # Find user in AD
        user_dn, attributes = self._find_user(username)
        if not user_dn:
            logger.warning(f"Authentication failed - user not found: {username}")
            raise InvalidCredentialsError("Invalid credentials")

        # Try to bind with user's credentials
        try:
            server = self._get_server()
            user_conn = Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
            )
            user_conn.unbind()
            logger.info(f"Successfully authenticated user: {username}")

        except LDAPInvalidCredentialsResult:
            logger.warning(f"Authentication failed - invalid password for user: {username}")
            raise InvalidCredentialsError("Invalid credentials")
        except Exception as e:
            logger.error(f"LDAP authentication error for {username}: {str(e)}")
            raise ADConnectionError(f"Authentication failed: {str(e)}")

        # Get user groups
        groups = self._get_user_groups(user_dn)

        # Extract user attributes
        user_attrs = self._extract_user_attributes(attributes)

        return UserInfo(
            username=username,
            dn=user_dn,
            display_name=user_attrs.get("display_name"),
            email=user_attrs.get("email"),
            groups=groups,
        )

    def test_connection(self) -> bool:
        """
        Test connection to AD server.

        Returns:
            True if connection successful

        Raises:
            ADConnectionError: If connection fails
        """
        try:
            self._get_connection()
            return True
        except ADConnectionError:
            raise
