"""Schedules in plain words, and a button flow to pick one.

Shared by everything that lets the owner choose *when* something runs
(`/rotation`, `/settings`), so the wording, the validation and the tap-through
picker are the same everywhere and nobody has to type a cron expression.
"""

from __future__ import annotations

from dataclasses import dataclass

from .scheduler import cron_is_valid

WEEKDAYS = {
    "mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu",
    "fri": "Fri", "sat": "Sat", "sun": "Sun",
}
MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
MONTH_DAYS = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
_CRON_DOW = {"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed", "4": "Thu",
             "5": "Fri", "6": "Sat", "7": "Sun", **WEEKDAYS}
_FREQUENCIES = {"daily": "Every day", "weekly": "Every week",
                "monthly": "Every month", "yearly": "Once a year"}


def parse_schedule(text: str) -> tuple[str | None, str]:
    """Turn ``daily 07:30`` / ``weekly fri 18:00`` / … into ``(cron, label)``.

    ``cron`` is None for "never". Raises ``ValueError`` with a message meant
    for the owner when the arguments don't make sense.
    """
    tokens = text.lower().split()
    if not tokens:
        raise ValueError("no schedule given")
    mode, rest = tokens[0], tokens[1:]

    if mode in ("never", "off", "none"):
        return None, "never (manual only)"
    if mode == "cron":
        cron = " ".join(rest)
        if not cron_is_valid(cron):
            raise ValueError("that is not a valid 5-field cron (m h dom mon dow)")
        return cron, f"custom cron {cron}"

    times = [t for t in rest if ":" in t]
    other = [t for t in rest if ":" not in t]
    if len(times) > 1 or len(other) > 1:
        raise ValueError("too many arguments")
    hour, minute = _parse_time(times[0]) if times else (9, 0)
    at = f"{hour:02d}:{minute:02d}"
    arg = other[0] if other else ""

    if mode == "daily":
        if arg:
            raise ValueError("daily only takes a time, e.g. daily 07:30")
        return f"{minute} {hour} * * *", f"every day at {at}"
    if mode == "weekly":
        day = (arg or "mon")[:3]
        if day not in WEEKDAYS:
            raise ValueError("weekday must be one of mon tue wed thu fri sat sun")
        return f"{minute} {hour} * * {day}", f"every week on {WEEKDAYS[day]} at {at}"
    if mode == "monthly":
        dom = _parse_int(arg or "1", 1, 28,
                         "day of month must be 1-28 (so it exists in every month)")
        return f"{minute} {hour} {dom} * *", f"every month on day {dom} at {at}"
    if mode == "yearly":
        day_s, sep, month_s = (arg or "01-01").replace("/", "-").partition("-")
        if not sep:
            raise ValueError("yearly date must be DD-MM, e.g. yearly 01-01")
        month = _parse_int(month_s, 1, 12, "month must be 1-12")
        dom = _parse_int(day_s, 1, MONTH_DAYS[month - 1],
                         "that day does not exist in that month")
        if (dom, month) == (29, 2):
            raise ValueError("29 Feb only exists in leap years — pick another day")
        return (f"{minute} {hour} {dom} {month} *",
                f"once a year on {dom} {MONTHS[month - 1]} at {at}")
    raise ValueError(f"unknown schedule '{mode}'")


def _parse_int(text: str, lo: int, hi: int, message: str) -> int:
    if not text.isdigit() or not lo <= int(text) <= hi:
        raise ValueError(message)
    return int(text)


def _parse_time(text: str) -> tuple[int, int]:
    hour_s, _, minute_s = text.partition(":")
    message = "time must be HH:MM (24h), e.g. 09:00"
    return _parse_int(hour_s, 0, 23, message), _parse_int(minute_s, 0, 59, message)


def describe(mode: str, day: str) -> str:
    """Plain-words summary of a schedule being picked (for the picker titles)."""
    if mode == "weekly":
        return f"Every week on {WEEKDAYS.get(day, day)}"
    if mode == "monthly":
        return f"Every month on day {day}"
    if mode == "yearly":
        dom, _, month = day.partition("-")
        name = MONTHS[int(month) - 1] if month.isdigit() and 1 <= int(month) <= 12 else month
        return f"Once a year on {dom} {name}"
    return "Every day"


def humanize_cron(cron: str) -> str:
    """A cron expression in words when it has a common shape, else the cron itself."""
    f = cron.split()
    if len(f) != 5 or not (f[0].isdigit() and f[1].isdigit()):
        return f"cron {cron}"
    minute, hour, dom, month, dow = f
    at = f"{int(hour):02d}:{int(minute):02d}"
    if dom == "*" and month == "*" and dow == "*":
        return f"every day at {at}"
    if dom == "*" and month == "*" and dow in _CRON_DOW:
        return f"every week on {_CRON_DOW[dow]} at {at}"
    if dom.isdigit() and month == "*" and dow == "*":
        return f"every month on day {int(dom)} at {at}"
    if dom.isdigit() and month.isdigit() and dow == "*" and 1 <= int(month) <= 12:
        return f"once a year on {int(dom)} {MONTHS[int(month) - 1]} at {at}"
    return f"cron {cron}"


@dataclass(frozen=True)
class Screen:
    """One step of a button flow: a message text and its inline keyboard."""
    text: str
    rows: list


class SchedulePicker:
    """Pick a schedule with buttons: frequency → day → hour → minute.

    ``prefix`` is what every button's callback data starts with (the plugin
    name, optionally followed by more context). After that the steps are

        pick:<mode> → (mo:<month> →) d:<mode>:<day> → t:<mode>:<day>:<hh>
        → ok:<mode>:<day>:<hh>:<mm>          ("-" stands for "no day": daily)

    Feed each button press to :meth:`step`: it returns the next ``Screen``, or
    — on the last tap — the choice as text for :func:`parse_schedule`, which
    validates it exactly like a typed schedule.
    """

    def __init__(self, prefix: str, back: str,
                 modes: tuple[str, ...] = ("daily", "weekly", "monthly", "yearly")):
        self.prefix = prefix
        self.back = back                    # callback data of the "Back" button
        self.modes = modes

    def frequency_rows(self) -> list:
        """Rows of "Every day / week / …" buttons that start the flow."""
        keys = [{"text": _FREQUENCIES[m], "callback_data": f"{self.prefix}:pick:{m}"}
                for m in self.modes]
        return [keys[i:i + 2] for i in range(0, len(keys), 2)]

    def step(self, verb: str, args: list[str]) -> Screen | str | None:
        if verb == "pick" and args[:1] == ["daily"] and "daily" in self.modes:
            return self._hours("daily", "-")
        if verb == "pick" and len(args) == 1 and args[0] in self.modes:
            return self._days(args[0])
        if (verb == "mo" and len(args) == 1 and args[0].isdigit()
                and 1 <= int(args[0]) <= 12):
            return self._days("yearly", int(args[0]))
        if verb == "d" and len(args) == 2:
            return self._hours(args[0], args[1])
        if verb == "t" and len(args) == 3:
            return self._minutes(*args)
        if verb == "ok" and len(args) == 4:
            mode, day, hour, minute = args
            return " ".join(x for x in (mode, "" if day == "-" else day,
                                        f"{hour}:{minute}") if x)
        return None

    def _grid(self, cells: list[tuple[str, str]], per_row: int) -> list:
        keys = [{"text": label, "callback_data": f"{self.prefix}:{data}"}
                for label, data in cells]
        rows = [keys[i:i + per_row] for i in range(0, len(keys), per_row)]
        return [*rows, [{"text": "⬅ Back", "callback_data": self.back}]]

    def _days(self, mode: str, month: int | None = None) -> Screen:
        if mode == "weekly":
            return Screen("🗓 Every week — which day?", self._grid(
                [(label, f"d:weekly:{day}") for day, label in WEEKDAYS.items()], 4))
        if mode == "monthly":
            return Screen("🗓 Every month — which day of the month?", self._grid(
                [(str(d), f"d:monthly:{d}") for d in range(1, 29)], 7))
        if month is None:
            return Screen("🗓 Once a year — which month?", self._grid(
                [(label, f"mo:{m}") for m, label in enumerate(MONTHS, 1)], 4))
        last = 28 if month == 2 else MONTH_DAYS[month - 1]
        return Screen(f"🗓 Once a year in {MONTHS[month - 1]} — which day?", self._grid(
            [(str(d), f"d:yearly:{d}-{month}") for d in range(1, last + 1)], 7))

    def _hours(self, mode: str, day: str) -> Screen:
        return Screen(f"🕘 {describe(mode, day)} — at what hour?", self._grid(
            [(f"{h:02d}", f"t:{mode}:{day}:{h:02d}") for h in range(24)], 6))

    def _minutes(self, mode: str, day: str, hour: str) -> Screen:
        return Screen(f"🕘 {describe(mode, day)} — exact time?", self._grid(
            [(f"{hour}:{m}", f"ok:{mode}:{day}:{hour}:{m}")
             for m in ("00", "15", "30", "45")], 4))
