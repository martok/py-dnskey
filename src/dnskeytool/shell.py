#!/usr/bin/env -S python3 -u
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from pprint import pprint
from typing import Optional

from .util import groupby_freeze
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


def fmt_timespan(span: timedelta, compressed=True) -> str:
    sec = int(span.total_seconds())
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


def main_rotate(tool: DnsSec, args: argparse.Namespace) -> int:
    if args.type != "ZSK":
        raise NotImplementedError("Only ZSKs can be rotated.")
    keys = tool.list_keys(args.ZONE, recursive=False)
    # ignore keys that are already expired and deleted or don't have a runtime
    keys = filter(lambda k: k.type == args.type, keys)
    keys = filter(lambda k: k.d_inactive is not None and k.state() != "DEL", keys)
    keys = list(keys)
    if len(keys) == 0:
        print("No keys qualified for renewal.")
        return 0
    # sanity checks on timing parameters
    prepub_intv: timedelta = args.prepublish
    life_intv: timedelta = args.lifetime
    post_intv: timedelta = args.postpublish
    overl_intv: timedelta = args.overlap
    second = timedelta(seconds=1)
    if prepub_intv.total_seconds() < 0:
        raise ValueError(f"Key pre-publication is negative")
    if life_intv.total_seconds() < 0:
        raise ValueError(f"Key lifetime is negative")
    if post_intv.total_seconds() < 0:
        raise ValueError(f"Key post-publication is negative")
    if overl_intv.total_seconds() < 0:
        raise ValueError(f"Key overlap is negative")
    if overl_intv >= life_intv:
        raise ValueError(
            f"Key overlap {fmt_timespan(overl_intv, False)} is longer than lifetime {fmt_timespan(life_intv, False)}")

    # begin planning
    plan = []
    # each algo is a separate list of keys
    by_algo = groupby_freeze(keys, lambda k: k.algo)
    for algo, akeys in by_algo.items():
        print(f"Zone: {args.ZONE}, signature algo: {algo}")
        # when new keys are made, always use the most recently generated one as a template
        # this allows the user to "inject" new key configs by hot-swapping a key between rotations
        template = sorted(akeys, key=lambda k: k.d_create or datetime.fromtimestamp(0))[-1]

        by_state = groupby_freeze(akeys, lambda k: k.state())
        if "ACT" not in by_state:
            print(f"No keys are currently active for algorithm {algo}, please fix and rerun...", file=sys.stderr)
            continue
        activekeys = sorted(by_state["ACT"], key=lambda k: k.d_inactive)

        # when a currently active key becomes inactive, there must be a key that becomes/is already
        # (depending on overlap). this is recursively true for any key currently active, not just the "main" / earliest
        # one: the other currently active keys are in their overlap phase, but we must check their successors here as
        # well in case the intervals are changed (or really short)
        for active in activekeys:
            ends = active.d_inactive + second
            # check if we need to fix the deletion time
            if active.d_delete is None or active.d_delete > ends + post_intv:
                plan.append(["set_times", active, dict(delete=active.d_inactive + post_intv)])
            successors = [k for k in akeys if k.state(ends) == "ACT"]
            if not successors:
                # need to make one!
                plan.append(["make_successor", template, active.d_inactive])
        # any other key state is just transitional or set on key creation, so we're done here

    if not plan:
        print("Nothing to do.")
        return 0

    if args.dry_run:
        pprint(plan)
        return 0

    def set_times(key: KeyFile, times):
        try:
            tool.key_settime(key, **times)
            return 0
        except BaseException as e:
            print(str(e), file=sys.stderr)
            return 2

    def make_successor(template: KeyFile, activate_at: datetime):
        activates = activate_at - overl_intv
        publishes = activates - prepub_intv
        inactivates = activates + life_intv
        deletes = inactivates + post_intv
        try:
            new_key = tool.key_gentemplate(template, publishes, activates, inactivates, deletes)
            return 0
        except BaseException as e:
            print(str(e), file=sys.stderr)
            return 2

    for task, *args in plan:
        fn = locals()[task]
        ret = fn(*args)
        if ret != 0:
            return ret
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

    p_rotate = sp.add_parser("rotate",
                             help="Rotate keys based on lifetime")
    p_rotate.add_argument("ZONE", type=str,
                          help="DNS zone to work on")
    p_rotate.add_argument("-t", "--type", choices=["ZSK", "KSK"], required=True, type=str.upper,
                          help="Filter keys by type")
    p_rotate.add_argument("-n", "--dry-run", action="store_true", default=False,
                          help="Don't perform action, just show plan")
    p_rotate.add_argument("-b", "--prepublish", default=parse_datetime_relative("1w"), type=parse_datetime_relative,
                          metavar="INTERVAL",
                          help="Time to publish keys before its activation date (Default: 1w)")
    p_rotate.add_argument("-l", "--lifetime", default=parse_datetime_relative("2w"), type=parse_datetime_relative,
                          metavar="INTERVAL",
                          help="Active lifetime of keys (Default: 2w)")
    p_rotate.add_argument("-o", "--overlap", default=parse_datetime_relative("1w"), type=parse_datetime_relative,
                          metavar="INTERVAL",
                          help="Overlap between active keys, calculated from the end of active phase (Default: 1w)")
    p_rotate.add_argument("-a", "--postpublish", default=parse_datetime_relative("1w"), type=parse_datetime_relative,
                          metavar="INTERVAL",
                          help="Time to publish keys after their deactivation date (Default: 1w)")
    p_rotate.set_defaults(func=main_rotate)

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
