import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .dnssec import DnsSec, KeyFile


def shortest_unique(*choices):
    def wrapped(func):
        def parser(inp: str):
            s = func(inp)
            # simple cases: not given or direct match?
            if s == "" or s in choices:
                return inp
            # uniquely specified?
            matching = [c for c in choices if c.startswith(s)]
            if len(matching) == 1:
                return matching[0]
            raise ValueError(f"Ambiguous argument {s}, could mean one of {' '.join(matching)}")

        parser.CHOICES = choices
        return parser

    return wrapped


@shortest_unique("PUB", "ACT", "INAC", "DEL", "FUT")
def parse_state(inp: str) -> str:
    return inp.upper()


@shortest_unique("ZONE", "ALG", "ID", "STATE", "DATE")
def parse_table_sort(inp: str) -> str:
    return inp.upper()


def parse_datetime_relative(inp: str) -> timedelta:
    # number of seconds
    try:
        ts = int(inp)
        return timedelta(seconds=ts)
    except ValueError:
        pass
    try:
        if inp.endswith("m"):
            return timedelta(minutes=int(inp[:-1]))
        if inp.endswith("h"):
            return timedelta(hours=int(inp[:-1]))
        if inp.endswith("d"):
            return timedelta(days=int(inp[:-1]))
        if inp.endswith("w"):
            return timedelta(weeks=int(inp[:-1]))
    except ValueError:
        pass
    raise ValueError(f"{inp} is not a valid relative date/time value")


def parse_datetime(inp: str) -> datetime:
    # DNS timestamp format YYYYMMDDHHmmss
    if len(inp) == 14 and inp.startswith("20"):
        try:
            y = int(inp[0:4])
            m = int(inp[4:6])
            d = int(inp[6:8])
            h = int(inp[8:10])
            n = int(inp[10:12])
            s = int(inp[12:14])
            return datetime(y, m, d, h, n, s)
        except ValueError:
            pass
    # unix timestamp (seconds)
    try:
        ts = int(inp)
        return datetime.fromtimestamp(ts)
    except ValueError:
        pass
    # ISO format
    try:
        return datetime.fromisoformat(inp)
    except ValueError:
        pass
    # time relative to now
    if inp.startswith("+"):
        return datetime.now() + parse_datetime_relative(inp[1:])
    raise ValueError(f"{inp} is not a valid date/time value")


def sort_by_field(field: str):
    if field == "ZONE":
        return lambda k: k.zone
    elif field == "ALG":
        return lambda k: k.algo
    elif field == "ID":
        return lambda k: k.keyid
    elif field == "STATE":
        return lambda k: k.state()
    elif field == "DATE":
        return lambda k: k.next_change() or datetime(3000, 1, 1)


def fmt_next_change(ref: datetime, key: KeyFile) -> str:
    n = key.next_change(ref=ref)
    if n is None:
        return "-"
    return str(n)


def fmt_datetime_relative(ref: datetime, date: Optional[datetime], compressed=True) -> str:
    if date is None:
        return "-"
    if date > ref:
        sign = "+"
        rel = date - ref
    else:
        sign = "-"
        rel = ref - date
    sec = int(rel.total_seconds())
    MINSEC = 60
    HOURSEC = MINSEC * 60
    DAYSEC = HOURSEC * 24
    WEEKSEC = DAYSEC * 7
    YEARSEC = DAYSEC * 365
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
    return sign + "".join(s)


def main_list(tool: DnsSec, args: argparse.Namespace) -> int:
    keys = tool.list_keys(args.ZONE, recursive=args.recurse)
    if args.when:
        when = args.when
    else:
        when = datetime.now()
    if args.state:
        keys = filter(lambda k: k.state == args.state, keys)
    if args.type:
        keys = filter(lambda k: k.type == args.type, keys)
    if args.sort:
        keys = sorted(keys, key=sort_by_field(args.sort))
    keys = list(keys)
    zone_width = max(len(k.zone) for k in keys) if keys else 0
    fields = [f"{'Type':6s} {'Algo':>5s} {'ID':>5s} {'State':7s}"]
    if args.recurse:
        fields.insert(0, f"{'Zone':{zone_width}s}")
    else:
        print("Zone: ", args.ZONE)
    if args.calendar:
        # crea publ acti inac dele
        fields.append(f"{'Crea':>4s} {'Pub':>4s} {'Act':>4s} {'Inac':>4s} {'Del':>4s} ")
    else:
        fields.append(f"{'Next Key Event':20s}")
    print(" ".join(fields))

    for key in keys:
        fields = [f"{key.type:6s} {key.algo:5d} {key.keyid:5d} {key.state(when):7s}"]
        if args.recurse:
            fields.insert(0, f"{key.zone:{zone_width}s}")
        if args.calendar:
            fields.append(f"{fmt_datetime_relative(when, key.d_create):>4s}")
            fields.append(f"{fmt_datetime_relative(when, key.d_publish):>4s}")
            fields.append(f"{fmt_datetime_relative(when, key.d_active):>4s}")
            fields.append(f"{fmt_datetime_relative(when, key.d_inactive):>4s}")
            fields.append(f"{fmt_datetime_relative(when, key.d_delete):>4s}")
        else:
            fields.append(f"{fmt_next_change(when, key):20s}")
        print(" ".join(fields))
        if args.print_record:
            print(f"{'':{zone_width}s}", key.dnskey_rr())
    print("")
    return 0


def main_archive(tool: DnsSec, args: argparse.Namespace) -> int:
    keys = tool.list_keys(args.ZONE, recursive=args.recurse)
    expired = []
    exp_ksk = 0
    for key in keys:
        if key.state() == "DEL":
            if key.type == "KSK":
                exp_ksk += 1
            expired.append(key)
    print(f"Found {len(expired)} expired keys, {exp_ksk} of which are key-signing keys.")
    plan = []
    for key in expired:
        if args.auto:
            year = str(key.d_inactive.year).rjust(4, "0")
            tdir = tool.path / (args.TARGET + year)
        else:
            tdir = tool.path / args.TARGET
        plan.append([key.type, key.path_rr, tdir])
        plan.append([key.type, key.path_pk, tdir])
    if not len(plan):
        return 0
    if args.dry_run:
        print("Would move: ")
    src: Path
    dst: Path
    for typ, src, dst in plan:
        if args.dry_run:
            print("  ", typ, " ", src, " -> ", dst)
        else:
            dst.mkdir(parents=True, exist_ok=True)
            src.rename(dst)
    return 0


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--dir", type=str,
                        help="directory containing key files")

    sp = parser.add_subparsers(metavar="COMMAND")
    sp.required = True

    p_list = sp.add_parser("list",
                           help="List currently present keys and their timing")
    p_list.add_argument("ZONE", type=str,
                        help="DNS zone to work on")
    p_list.add_argument("--when", default=None, type=parse_datetime, metavar="DATETIME",
                        help="When computing states, use DATETIME instead of current")
    p_list.add_argument("-r", "--recurse", action="store_true", default=False,
                        help="Show key for all zones below the given one")
    p_list.add_argument("-s", "--state", choices=parse_state.CHOICES, default="", type=parse_state, metavar="STATE",
                        help="Filter keys by current state")
    p_list.add_argument("-t", "--type", choices=["ZSK", "KSK"], default="", type=str.upper,
                        help="Filter keys by type")
    p_list.add_argument("-o", "--sort", choices=parse_table_sort.CHOICES, default="", type=parse_table_sort,
                        metavar="FIELD",
                        help="Sort keys by attribute")
    p_list.add_argument("--print-record", action="store_true", default=False,
                        help="Output DNSKEY RR payload in table")
    p_list.add_argument("-c", "--calendar", action="store_true", default=False,
                        help="Show relative time to each state change (default: only timestamp of next change)")
    p_list.set_defaults(func=main_list)

    p_archive = sp.add_parser("archive",
                              help="Move expired keys to archive location")
    p_archive.add_argument("ZONE", type=str,
                           help="DNS zone to work on")
    p_archive.add_argument("TARGET", type=str,
                           help="Target path to move to")
    p_archive.add_argument("-r", "--recurse", action="store_true", default=False,
                           help="Recursively act on zones below the given one")
    p_archive.add_argument("-n", "--dry-run", action="store_true", default=False,
                           help="Don't perform action, just show plan")
    p_archive.add_argument("--auto", action="store_true", default=False,
                           help="Automatically append year of inactivation to TARGET")
    p_archive.set_defaults(func=main_archive)

    args = parser.parse_args()

    if args.dir:
        keydir = Path(args.dir)
        if not keydir.exists():
            raise IOError(f"Key directory '{args.dir}' not found!")
    else:
        keydir = Path.cwd()

    if args.ZONE:
        if not args.ZONE.endswith("."):
            args.ZONE += "."
            print(f"Zone is missing root label, assuming fully qualified: {args.ZONE}", file=sys.stderr)

    tool = DnsSec(keydir)

    return args.func(tool, args)


if __name__ == "__main__":
    sys.exit(main())
