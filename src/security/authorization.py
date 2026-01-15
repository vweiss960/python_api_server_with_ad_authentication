"""
Authorization and group-based access control.
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import fnmatch

from src.config import AuthorizationConfig, AuthorizationRule
from src.utils.logger import get_logger
from src.utils.errors import AuthorizationError

logger = get_logger("authorization")


class AuthorizationManager:
    """Manages authorization rules and group-based access control."""

    def __init__(self, config: AuthorizationConfig):
        """
        Initialize authorization manager.

        Args:
            config: Authorization configuration with rules
        """
        self.config = config
        self._compiled_rules = self._compile_rules(config.rules)

    def _compile_rules(self, rules: List[AuthorizationRule]) -> List[Dict[str, Any]]:
        """
        Compile authorization rules for efficient matching.

        Args:
            rules: List of AuthorizationRule objects

        Returns:
            List of compiled rules
        """
        compiled = []
        for rule in rules:
            compiled.append({
                "path_pattern": rule.path,
                "groups": rule.groups,
                "require": rule.require,
                "exclude_groups": rule.exclude_groups or [],
                "original": rule,
            })
        logger.info(f"Compiled {len(compiled)} authorization rules")
        return compiled

    def _extract_simple_group_name(self, group_dn: str) -> str:
        """
        Extract simple group name from DN.

        Args:
            group_dn: Group distinguished name or simple name

        Returns:
            Simple group name (CN part from DN, or original if already simple)
        """
        if "," not in group_dn:
            # Already a simple name
            return group_dn

        # Extract CN from DN
        try:
            parts = group_dn.split(",")
            cn_part = parts[0]
            if cn_part.startswith("CN="):
                return cn_part[3:]
        except:
            pass

        return group_dn

    def _normalize_groups(self, groups: List[str], use_simple_names: bool = True) -> List[str]:
        """
        Normalize group list (optionally extract simple names).

        Args:
            groups: List of group names/DNs
            use_simple_names: If True, extract CN from DNs

        Returns:
            Normalized group list
        """
        if not use_simple_names:
            return groups

        normalized = []
        for group in groups:
            normalized.append(self._extract_simple_group_name(group))
        return normalized

    def _path_matches(self, request_path: str, pattern: str) -> bool:
        """
        Check if request path matches authorization rule pattern.

        Supports wildcards:
        - /api/admin/* - matches /api/admin/users, /api/admin/settings, etc.
        - /api/data/* - matches /api/data/read, /api/data/write, etc.

        Args:
            request_path: The request path (e.g., /api/admin/users)
            pattern: The pattern to match against

        Returns:
            True if path matches pattern
        """
        # Convert path pattern to regex
        # /api/admin/* becomes /api/admin/.*
        regex_pattern = pattern.replace("*", "*")
        return fnmatch.fnmatch(request_path, regex_pattern)

    def find_applicable_rules(self, path: str) -> List[Dict[str, Any]]:
        """
        Find all authorization rules applicable to a path.

        Args:
            path: Request path

        Returns:
            List of applicable rules
        """
        applicable = []
        for rule in self._compiled_rules:
            if self._path_matches(path, rule["path_pattern"]):
                applicable.append(rule)
        return applicable

    def check_authorization(
        self,
        path: str,
        user_groups: List[str],
    ) -> tuple[bool, Optional[List[str]], Optional[str]]:
        """
        Check if user is authorized for a path.

        Args:
            path: Request path
            user_groups: List of groups user belongs to

        Returns:
            Tuple of (authorized, required_groups, error_message)
            - authorized: True if user is authorized
            - required_groups: Groups required for this path (if authorization failed)
            - error_message: Human-readable error message
        """
        # Find applicable rules for this path
        applicable_rules = self.find_applicable_rules(path)

        # If no rules apply, authorization passes
        if not applicable_rules:
            logger.debug(f"No authorization rules found for path: {path}")
            return True, None, None

        # Normalize user groups
        normalized_user_groups = self._normalize_groups(
            user_groups,
            use_simple_names=self.config.use_simple_names,
        )

        # Check each applicable rule
        for rule in applicable_rules:
            required_groups = rule["groups"]
            exclude_groups = rule["exclude_groups"]
            require_type = rule["require"]

            # Normalize required groups
            normalized_required = self._normalize_groups(
                required_groups,
                use_simple_names=self.config.use_simple_names,
            )

            # Check exclusions first
            if exclude_groups:
                normalized_exclude = self._normalize_groups(
                    exclude_groups,
                    use_simple_names=self.config.use_simple_names,
                )
                if any(g in normalized_user_groups for g in normalized_exclude):
                    logger.warning(
                        f"User is in excluded group for path {path}. "
                        f"User groups: {normalized_user_groups}, "
                        f"Excluded groups: {normalized_exclude}"
                    )
                    return False, normalized_required, f"Access denied - user is in restricted group"

            # Check required groups based on require type
            if require_type == "any":
                # User must be in at least one required group
                if any(g in normalized_user_groups for g in normalized_required):
                    logger.info(
                        f"User authorized for path {path}. "
                        f"User groups: {normalized_user_groups}, "
                        f"Required: {normalized_required}"
                    )
                    return True, None, None
            elif require_type == "all":
                # User must be in all required groups
                if all(g in normalized_user_groups for g in normalized_required):
                    logger.info(
                        f"User authorized for path {path}. "
                        f"User groups: {normalized_user_groups}, "
                        f"Required: {normalized_required}"
                    )
                    return True, None, None

        # If we get here, authorization failed
        all_required_groups = list(set(
            g for rule in applicable_rules for g in rule["groups"]
        ))
        normalized_required = self._normalize_groups(
            all_required_groups,
            use_simple_names=self.config.use_simple_names,
        )

        logger.warning(
            f"User authorization failed for path {path}. "
            f"User groups: {normalized_user_groups}, "
            f"Required groups: {normalized_required}"
        )

        return False, normalized_required, "Insufficient permissions"

    def get_all_rules(self) -> List[AuthorizationRule]:
        """
        Get all configured authorization rules.

        Returns:
            List of AuthorizationRule objects
        """
        return [rule["original"] for rule in self._compiled_rules]

    def validate_rules(self) -> List[str]:
        """
        Validate authorization rules configuration.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not self._compiled_rules:
            # No rules is valid - just means no path-based authorization
            logger.info("No authorization rules configured")
            return errors

        for i, rule in enumerate(self._compiled_rules):
            if not rule["path_pattern"]:
                errors.append(f"Rule {i}: Path pattern is required")
            if not rule["groups"]:
                errors.append(f"Rule {i}: At least one group is required")
            if rule["require"] not in ["any", "all"]:
                errors.append(f"Rule {i}: 'require' must be 'any' or 'all'")

        if errors:
            logger.error(f"Authorization rules validation failed: {errors}")
        else:
            logger.info("Authorization rules validation passed")

        return errors
