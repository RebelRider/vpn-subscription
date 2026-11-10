"""Pure daily Qwen due slots; Europe/Moscow is authoritative in every timezone."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo as Timezone
import math
from zoneinfo import ZoneInfo


MOSCOW = ZoneInfo("Europe/Moscow")
DAILY_HOUR = 3
DAILY_MINUTE = 1


def _local_clock(now_epoch: float) -> datetime:
    if type(now_epoch) not in (int, float):
        raise ValueError("Schedule clock must be a finite epoch")
    try:
        if not math.isfinite(float(now_epoch)):
            raise ValueError
        return datetime.fromtimestamp(now_epoch, timezone.utc).astimezone(MOSCOW)
    except (OverflowError, OSError, ValueError):
        raise ValueError("Schedule clock is outside the supported calendar") from None


def _today_slot(now_epoch: float) -> tuple[datetime, datetime]:
    now = _local_clock(now_epoch)
    return now, now.replace(hour=DAILY_HOUR, minute=DAILY_MINUTE, second=0, microsecond=0)


def latest_due_slot(now_epoch: float) -> tuple[str, float]:
    """Latest elapsed slot, not a backlog: a missed week yields one due date.

    The worker persists this Moscow date only after its bounded attempt. A
    kernel lock and that persisted slot provide idempotence across minute polls,
    wake/login and restarted workers; this function performs no filesystem I/O.
    """
    now, due = _today_slot(now_epoch)
    try:
        if now < due:
            due -= timedelta(days=1)
        return due.date().isoformat(), due.timestamp()
    except (OverflowError, OSError, ValueError):
        raise ValueError("Due date is outside the supported calendar") from None


def next_scheduled_at(now_epoch: float) -> float:
    """Return the strictly future Moscow03:01, independent of host timezone."""
    now, due = _today_slot(now_epoch)
    try:
        if due <= now:
            due += timedelta(days=1)
        return due.timestamp()
    except (OverflowError, OSError, ValueError):
        raise ValueError("Next due date is outside the supported calendar") from None


def calendar_for_local_timezone(now_epoch: float, tzinfo: Timezone) -> dict[str, int]:
    """A launchd calendar hint for the next due slot in the machine's timezone.

    launchd follows the machine's wall clock, not TZ in an environment variable.
    Calendar hints can drift after timezone/DST changes; the worker's minute
    poll must always gate actual work using latest_due_slot instead.
    """
    if not isinstance(tzinfo, Timezone):
        raise ValueError("Calendar conversion requires an explicit timezone")
    due = datetime.fromtimestamp(next_scheduled_at(now_epoch), timezone.utc).astimezone(tzinfo)
    return {"Hour": due.hour, "Minute": due.minute}
