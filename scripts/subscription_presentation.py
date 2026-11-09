"""Deterministic Happ presentation, displaying verified timestamps in Moscow.

The client refresh time never supplies a validation date. The title ages from
the last successful published validation. Historical per-node evidence remains
separate in diagnostics; stricter publication checks live in local_probe.
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import ipaddress
import math
import re
import time

VERSION = 2
STALE_AFTER_SECONDS = 72 * 3600
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
TITLE_TIMEZONE = ZoneInfo("Europe/Moscow")


def validation_time(value: object, *, now: float | None = None) -> datetime:
    """Reject invented, naive, malformed and future dates rather than guessing."""
    reference = time.time() if now is None else now
    try:
        if (isinstance(reference, bool) or not isinstance(reference, (int, float))
                or not math.isfinite(reference) or reference <= 0
                or not isinstance(value, str) or len(value) > 80):
            raise ValueError
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError
        epoch = stamp.timestamp()
        if not math.isfinite(epoch) or not 0 < epoch <= reference:
            raise ValueError
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        raise RuntimeError("Invalid or future subscription validation timestamp") from None


def title(status: dict, *, now: float | None = None) -> str:
    """Render the last published validation date; STALE requires more than 72h."""
    reference = time.time() if now is None else now
    if not isinstance(status, dict):
        raise RuntimeError("Invalid subscription presentation metadata")
    generated = validation_time(status.get("generated_at"), now=reference)
    retained = status.get("retained_nodes", [])
    if not isinstance(retained, list) or not all(isinstance(node, dict) for node in retained):
        raise RuntimeError("Invalid retained subscription presentation metadata")
    stale = reference - generated.timestamp() > STALE_AFTER_SECONDS
    displayed = generated.astimezone(TITLE_TIMEZONE)
    date = (f"{displayed.day:02d}{MONTHS[displayed.month - 1]}{displayed.year} "
            f"{displayed.hour:02d}:{displayed.minute:02d}")
    # Happ documents a 25-character profile-title limit. Keep the full saved
    # timestamp for fresh profiles and in metadata; never truncate into a
    # misleading date when adding the stale marker.
    return "#profile-title: BL VPN [STALE]" if stale else f"#profile-title: BL VPN [{date}]"


def server_label(rank: int, country: str | None, city: str | None,
                 address: str | None, *, version: int = VERSION) -> str:
    """Name only observed public exit addresses, without DNS or endpoint guesses."""
    if type(rank) is not int or rank < 1:
        raise ValueError("Invalid subscription presentation rank")
    if type(version) is not int or version not in (1, VERSION):
        raise RuntimeError("Unsupported subscription presentation version")
    country = country.strip().upper() if isinstance(country, str) else ""
    city = city.strip() if isinstance(city, str) else ""
    city = re.sub(r"\s+\([^()]+\)\s*$", "", city).strip()
    if version == VERSION:
        # Version 1 stays byte-compatible with immutable historical fragments;
        # the URI adapter encodes their text rather than emitting raw headers.
        city = re.sub(r"[\x00-\x1f\x7f]", " ", city)
        city = re.sub(r"\s+", " ", city).strip()[:200]
    known = country not in {"XX", "ZZ"} and re.fullmatch(r"[A-Z]{2}", country)
    if known:
        flag = "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in country)
        prefix = f"{flag} {country}"
        if version == 1:
            label = f"{prefix} | {city} | {rank}" if city else f"{prefix} | {rank}"
        else:
            label = f"{prefix}{', ' + city if city else ''}  |{rank}|"
    else:
        label = f"🌐 | {rank}" if version == 1 else f"🌐  |{rank}|"
    if isinstance(address, str):
        try:
            parsed = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            return label
        if (parsed.is_global and not parsed.is_multicast
                and (version == 1 or not getattr(parsed, "scope_id", None))):
            label += f" | [{parsed}]" if version == 1 else f"   [{parsed}]"
    return label
