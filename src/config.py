"""
Configuration loading and management for the API server.

Supports YAML/JSON configuration files with environment variable overrides.
"""

import os
import yaml
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 8443
    tls_enabled: bool = True
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    cert_chain: Optional[str] = None


@dataclass
class ADConfig:
    """Active Directory configuration."""
    server: str
    use_ssl: bool = False
    base_dn: str
    bind_dn: str
    bind_password: str
    user_search_filter: str = "(&(objectClass=user)(sAMAccountName={username}))"
    group_base_dn: Optional[str] = None
    group_search_filter: str = "(&(objectClass=group)(member={user_dn}))"
    group_attribute: str = "memberOf"
    timeout: int = 30


@dataclass
class AuthorizationRule:
    """Single authorization rule."""
    path: str
    groups: List[str]
    require: str = "any"  # "any" or "all"
    exclude_groups: Optional[List[str]] = None


@dataclass
class AuthorizationConfig:
    """Authorization configuration."""
    group_attribute: str = "memberOf"
    use_simple_names: bool = True
    rules: List[AuthorizationRule] = None

    def __post_init__(self):
        if self.rules is None:
            self.rules = []


@dataclass
class JWTConfig:
    """JWT configuration."""
    secret: str
    expiration_hours: int = 24
    include_groups: bool = True
    algorithm: str = "HS256"


@dataclass
class CertificateConfig:
    """Certificate configuration."""
    custom_ca_dir: Optional[str] = None


@dataclass
class Config:
    """Main configuration class."""
    server: ServerConfig
    ad: ADConfig
    authorization: AuthorizationConfig
    jwt: JWTConfig
    certificates: CertificateConfig


class ConfigLoader:
    """Loads and manages application configuration."""

    def __init__(self, config_path: str):
        """
        Initialize config loader with a path to a configuration file.

        Args:
            config_path: Path to YAML or JSON configuration file
        """
        self.config_path = Path(config_path)
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        self.raw_config = self._load_file()
        self.config = self._parse_config()

    def _load_file(self) -> Dict[str, Any]:
        """Load configuration file (YAML or JSON)."""
        with open(self.config_path, "r") as f:
            if self.config_path.suffix.lower() in [".yaml", ".yml"]:
                return yaml.safe_load(f) or {}
            elif self.config_path.suffix.lower() == ".json":
                return json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {self.config_path.suffix}")

    def _resolve_env_vars(self, value: Any) -> Any:
        """
        Recursively resolve environment variables in configuration values.

        Supports ${VAR_NAME} syntax for environment variables.
        """
        if isinstance(value, str):
            if value.startswith("${") and value.endswith("}"):
                var_name = value[2:-1]
                env_value = os.environ.get(var_name)
                if env_value is None:
                    raise ValueError(f"Environment variable not set: {var_name}")
                return env_value
            return value
        elif isinstance(value, dict):
            return {k: self._resolve_env_vars(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._resolve_env_vars(item) for item in value]
        return value

    def _parse_config(self) -> Config:
        """Parse configuration into dataclass objects."""
        # Resolve environment variables
        config_dict = self._resolve_env_vars(self.raw_config)

        # Parse server config
        server_dict = config_dict.get("server", {})
        server = ServerConfig(**server_dict)

        # Parse AD config
        ad_dict = config_dict.get("ad", {})
        ad = ADConfig(**ad_dict)

        # Parse authorization config
        auth_dict = config_dict.get("authorization", {})
        rules_list = []
        for rule in auth_dict.get("rules", []):
            rules_list.append(AuthorizationRule(**rule))
        auth_dict["rules"] = rules_list
        authorization = AuthorizationConfig(**auth_dict)

        # Parse JWT config
        jwt_dict = config_dict.get("jwt", {})
        jwt = JWTConfig(**jwt_dict)

        # Parse certificate config
        cert_dict = config_dict.get("certificates", {})
        certificates = CertificateConfig(**cert_dict)

        return Config(
            server=server,
            ad=ad,
            authorization=authorization,
            jwt=jwt,
            certificates=certificates,
        )

    def get(self) -> Config:
        """Get parsed configuration object."""
        return self.config

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of errors (if any).

        Returns:
            List of error messages, empty if valid
        """
        errors = []

        # Validate server config
        if self.config.server.tls_enabled:
            if not self.config.server.cert_file:
                errors.append("Server TLS enabled but cert_file not specified")
            elif not Path(self.config.server.cert_file).exists():
                errors.append(f"Certificate file not found: {self.config.server.cert_file}")

            if not self.config.server.key_file:
                errors.append("Server TLS enabled but key_file not specified")
            elif not Path(self.config.server.key_file).exists():
                errors.append(f"Key file not found: {self.config.server.key_file}")

        # Validate AD config
        if not self.config.ad.server:
            errors.append("AD server not specified")
        if not self.config.ad.base_dn:
            errors.append("AD base_dn not specified")
        if not self.config.ad.bind_dn:
            errors.append("AD bind_dn not specified")
        if not self.config.ad.bind_password:
            errors.append("AD bind_password not specified")

        # Validate JWT config
        if not self.config.jwt.secret:
            errors.append("JWT secret not specified")

        # Validate custom CA directory if specified
        if self.config.certificates.custom_ca_dir:
            ca_dir = Path(self.config.certificates.custom_ca_dir)
            if not ca_dir.exists():
                errors.append(f"Custom CA directory not found: {self.config.certificates.custom_ca_dir}")

        return errors
