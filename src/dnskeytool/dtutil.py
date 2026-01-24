from datetime import datetime, timezone, timedelta
from typing import Optional


def nowutc():
    return datetime.now(timezone.utc)


def parse_dnsdatetime(colon_line: str) -> datetime:
    if " " in colon_line:
        words = colon_line.split()
        dt = words[2]
    else:
        dt = colon_line
    if len(dt) != len("yyyymmddhhmmss"):
        raise ValueError(f"Unexpected date format: '{colon_line}'")
    d = datetime.strptime(dt, "%Y%m%d%H%M%S")
    # date strings in files are always UTC
    return d.replace(tzinfo=timezone.utc)


def fmt_dnsdatetime(date: datetime) -> str:
    return date.astimezone(timezone.utc).strftime("%Y%m%d%H%M%S")


# this follows the dnssec-settime convention of
# "years (defined as 365 24-hour days, ignoring leap years), months (defined as 30 24-hour days)"
MINSEC = 60
HOURSEC = MINSEC * 60
DAYSEC = HOURSEC * 24
WEEKSEC = DAYSEC * 7
MONTHSEC = DAYSEC * 30
YEARSEC = DAYSEC * 365


def parse_datetime_relative(inp: str) -> timedelta:
    # number of seconds
    try:
        ts = int(inp)
        return timedelta(seconds=ts)
    except ValueError:
        pass
    try:
        if inp.endswith("mi"):
            return timedelta(minutes=int(inp[:-2]))
        if inp.endswith("h"):
            return timedelta(hours=int(inp[:-1]))
        if inp.endswith("d"):
            return timedelta(days=int(inp[:-1]))
        if inp.endswith("w"):
            return timedelta(weeks=int(inp[:-1]))
        if inp.endswith("m"):
            return timedelta(days=int(inp[:-1]) * 30)
        if inp.endswith("y"):
            return timedelta(days=int(inp[:-1]) * 365)
    except ValueError:
        pass
    raise ValueError(f"{inp} is not a valid relative date/time value")


def parse_datetime(inp: str) -> datetime:
    # DNS timestamp format YYYYMMDDHHmmss
    if len(inp) == 14 and inp.startswith("20"):
        try:
            return parse_dnsdatetime(inp)
        except ValueError:
            pass
    # unix timestamp (seconds)
    try:
        ts = int(inp)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except ValueError:
        pass
    # ISO format
    try:
        d = datetime.fromisoformat(inp)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d
    except ValueError:
        pass
    # time relative to now
    if inp.startswith("+"):
        return nowutc() + parse_datetime_relative(inp[1:])
    raise ValueError(f"{inp} is not a valid date/time value")


def fmt_timespan(span: timedelta, compressed=True) -> str:
    sec = int(span.total_seconds())
    s = []
    if sec >= YEARSEC * 1.2:
        s.append(f"{sec // YEARSEC}y")
        sec = sec % YEARSEC
    if sec >= WEEKSEC * 1.2:
        s.append(f"{sec // WEEKSEC}w")
        sec = sec % WEEKSEC
    if sec >= DAYSEC * 1.2:
        s.append(f"{sec // DAYSEC}d")
        sec = sec % DAYSEC
    if sec >= HOURSEC * 1.2:
        s.append(f"{sec // HOURSEC}h")
        sec = sec % HOURSEC
    if sec >= MINSEC * 1.2:
        s.append(f"{sec // MINSEC}m")
        sec = sec % MINSEC
    if sec >= 0:
        s.append(f"{sec}s")
    if compressed:
        s = s[:1]
    return "".join(s)


def fmt_datetime_relative(ref: datetime, date: Optional[datetime], compressed=True) -> str:
    if date is None:
        return "-"
    if date > ref:
        sign = "+"
        rel = date - ref
    else:
        sign = "-"
        rel = ref - date
    return sign + fmt_timespan(rel, compressed)
