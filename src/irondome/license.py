"""License enforcement for PicoDome.

Personal use is free. Commercial use requires a Shogun license.
See LICENSE for details.
"""

from __future__ import annotations

import logging
import os
from enum import Enum

logger = logging.getLogger("irondome.license")

__all__ = ["LicenseTier", "LicenseInfo", "check_license", "get_license_info"]


class LicenseTier(str, Enum):
    """License tier levels."""

    PERSONAL = "personal"
    COMMERCIAL = "commercial"
    ENTERPRISE = "enterprise"


class LicenseInfo:
    """License information for the current installation."""

    def __init__(
        self,
        tier: LicenseTier = LicenseTier.PERSONAL,
        holder: str = "",
        organization: str = "",
        expires: str | None = None,
        key: str = "",
        source: str = "default",
    ):
        self.tier = tier
        self.holder = holder
        self.organization = organization
        self.expires = expires
        self.key = key
        self.source = source

    @property
    def is_commercial(self) -> bool:
        return self.tier in (LicenseTier.COMMERCIAL, LicenseTier.ENTERPRISE)

    @property
    def is_personal(self) -> bool:
        return self.tier == LicenseTier.PERSONAL

    def to_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "holder": self.holder,
            "organization": self.organization,
            "expires": self.expires,
            "source": self.source,
        }

    def __repr__(self) -> str:
        return f"LicenseInfo(tier={self.tier.value}, holder={self.holder!r})"


# ─── Global license state ──────────────────────────────────────────────────

_cached_license: LicenseInfo | None = None


def _reset_cache() -> None:
    """Reset the cached license (for testing)."""
    global _cached_license
    _cached_license = None


def check_license() -> LicenseInfo:
    """
    Check the current license status.

    Resolution order:
    1. IRONDOME_LICENSE_KEY environment variable
    2. .irondome-license file in current directory
    3. ~/.irondome/license.json user-level license
    4. Default: personal use

    Returns:
        LicenseInfo with the resolved license tier.
    """
    global _cached_license
    if _cached_license is not None:
        return _cached_license

    # 1. Environment variable
    env_key = os.environ.get("IRONDOME_LICENSE_KEY", "").strip()
    if env_key:
        info = _validate_key(env_key)
        if info:
            _cached_license = info
            return info

    # 2. Local license file
    local_path = os.path.join(os.getcwd(), ".irondome-license")
    if os.path.isfile(local_path):
        info = _load_license_file(local_path)
        if info:
            _cached_license = info
            return info

    # 3. User-level license file
    user_path = os.path.expanduser("~/.irondome/license.json")
    if os.path.isfile(user_path):
        info = _load_license_file(user_path)
        if info:
            _cached_license = info
            return info

    # 4. Default: personal use
    _cached_license = LicenseInfo(
        tier=LicenseTier.PERSONAL,
        holder=os.environ.get("USER", "unknown"),
        source="default",
    )
    logger.info("No commercial license found — running in personal use mode")
    return _cached_license


def get_license_info() -> LicenseInfo:
    """Get license info without side effects."""
    return check_license()


def _validate_key(key: str) -> LicenseInfo | None:
    """
    Validate a license key.

    In the current version, this is a placeholder that Shogun will
    replace with actual key validation. For now, commercial keys
    follow the format: shogun-<tier>-<org>-<hash>

    Args:
        key: License key string.

    Returns:
        LicenseInfo if valid, None otherwise.
    """
    if not key.startswith("shogun-"):
        logger.warning("Invalid license key format: must start with 'shogun-'")
        return None

    parts = key.split("-")
    if len(parts) < 3:
        logger.warning("Invalid license key format: too few parts")
        return None

    tier_str = parts[1]
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        logger.warning("Invalid license key tier: %s", tier_str)
        return None

    # Shogun will replace this with actual cryptographic verification
    # For now, accept any well-formed key
    org = parts[2] if len(parts) > 2 else ""

    return LicenseInfo(
        tier=tier,
        holder="",
        organization=org,
        key=key[:8] + "..." if len(key) > 8 else key,
        source="key",
    )


def _load_license_file(path: str) -> LicenseInfo | None:
    """
    Load license info from a JSON file.

    Args:
        path: Path to license file.

    Returns:
        LicenseInfo if valid, None otherwise.
    """
    import json

    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load license file %s: %s", path, e)
        return None

    key = data.get("key", "")
    if key:
        info = _validate_key(key)
        if info:
            info.holder = data.get("holder", "")
            info.organization = data.get("organization", info.organization)
            info.expires = data.get("expires")
            info.source = f"file:{path}"
            return info

    # Fallback: check tier directly
    tier_str = data.get("tier", "personal")
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        logger.warning("Invalid license tier in %s: %s", path, tier_str)
        return None

    return LicenseInfo(
        tier=tier,
        holder=data.get("holder", ""),
        organization=data.get("organization", ""),
        expires=data.get("expires"),
        source=f"file:{path}",
    )


def require_commercial(feature: str = "") -> bool:
    """
    Check if a commercial license is active.

    Logs a warning if running in personal mode and returns False.
    Returns True if commercial license is present.

    Args:
        feature: Optional feature name for the warning message.

    Returns:
        True if commercial license, False if personal.
    """
    info = check_license()
    if info.is_commercial:
        return True

    feature_msg = f" '{feature}'" if feature else ""
    logger.warning(
        "Shogun command center license required for%s. "
        "Running in personal use mode — no command center access. "
        "See https://github.com/KirkForge/PicoShogun for commercial licensing.",
        feature_msg,
    )
    return False
