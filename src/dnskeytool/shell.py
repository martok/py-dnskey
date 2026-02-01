#!/usr/bin/env -S python3 -u
import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from pprint import pprint
from typing import List

import dns

from .tui import ListAppendAction, TablePrinter, JSONPrinter, ParagraphFormatter, MultipleEnumAction, EnumAction
from .dnssec import DnsSec, KeyFile
from .dtutil import parse_datetime_relative, parse_datetime, fmt_timespan, \
    fmt_datetime_relative, nowutc
from .lookup import PublishedKeyCollection, shorten_dns
from .resolver import StubResolver, RecursiveResolver
from .util import groupby_freeze


class ResolverListAction(ListAppendAction):
    def filter(self, arg):
        if dns.inet.is_address(arg):
            return arg
        if arg.upper() == "RECURSE":
            return arg
        raise ValueError(f"Invalid argument for resolver: {arg}")

    def combine(self, oldlist: List, newlist: List) -> List:
        return list(set(oldlist).union(newlist))


def sort_by_field(field: str):
    match field:
        case "ZONE":
            return lambda k: k.zone
        case "TYPE":
            return lambda k: k.type
        case "ALG":
            return lambda k: k.algo
        case "ID":
            return lambda k: k.keyid
        case "STATE":
            return lambda k: k.state()
        case "DATE":
            def sorter(k):
                try:
                    return k.next_change() or datetime(3000, 1, 1, tzinfo=timezone.utc)
                except ValueError:
                    return datetime(1000, 1, 1, tzinfo=timezone.utc)
            return sorter
        case "HOST":
            return lambda k: tuple(reversed(k.zone.split(".")))
        case _:
            raise ValueError(f"Invalid sort field: {field}")


def fmt_next_change(ref: datetime, key: KeyFile) -> str:
    try:
        n = key.next_change(ref=ref)
    except ValueError as e:
        return str(e)
    if n is None:
        return "-"
    return n.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")


def fmt_server_name(name: str):
    return shorten_dns(name)


def main_list(tool: DnsSec, args: argparse.Namespace) -> int:
    keys = tool.list_keys(args.ZONE, recursive=args.recurse)
    if args.when:
        when = args.when
    else:
        when = nowutc()
    if args.state:
        keys = args.state.as_filter(keys, key=lambda k: k.state(when))
    if args.type:
        keys = args.type.as_filter(keys, key="type")
    if args.sort:
        keys = args.sort.as_multi_sorter(keys, key=sort_by_field)
    keys = list(keys)
    zone_width = max(len(k.zone) for k in keys) if keys else 4

    match args.output:
        case "JSON":
            printer = JSONPrinter()
        case "TABLE" | "GRID":
            printer = TablePrinter()
            printer.with_grid = args.output == "GRID"
        case _:
            raise ValueError("Invalid output format")
    printer.start_header()
    if args.recurse:
        printer.add("Zone", w=zone_width)
    else:
        print("Zone: ", args.ZONE)
    if args.permissions:
        printer.add("Perms", w=5, align="^")
    printer.add("Type", w=6)
    printer.add("Algo", w=5, align=">")
    printer.add("ID", w=5, align=">")
    printer.add("State", w=7, align=">")
    if args.calendar:
        # crea publ acti inac dele
        printer.add("Crea", w=4, align=">")
        printer.add("Pub", w=4, align=">")
        printer.add("Act", w=4, align=">")
        printer.add("Inac", w=4, align=">")
        printer.add("Del", w=4, align=">")
    else:
        printer.add("Next Key Event", w=16)
    if args.verify_ns:
        if args.resolver == "RECURSE":
            res = RecursiveResolver()
        else:
            res = StubResolver(args.resolver)
        res.prefer_v4 = args.ip == 4
        key_collection = PublishedKeyCollection(res)
        servers = [ns for ns in args.verify_ns if ns is not None]
        if servers:
            key_collection.set_explicit_nameservers(servers)
        zones = {k.zone for k in keys}
        print("Collecting state of zone: ", end="")
        for zone in zones:
            print(zone, end=" ", flush=True)
            key_collection.query_zone(zone)
        print("")
        print("Responses from nameservers: ", " ".join(key_collection.contacted_servers()))
        print("")
        for ns in key_collection.contacted_servers():
            printer.add(fmt_server_name(ns) if ns is not None else "?")
    printer.done()

    for key in keys:
        printer.start_row()
        if args.recurse:
            printer.add(key.zone)
        if args.permissions:
            printer.add('*' if key.set_perms(check_only=True) else '')
        printer.add(key.type)
        printer.add(key.algo * (-1 if key.is_supported() is False else 1))
        printer.add(key.keyid)
        printer.add(key.state(when))
        if args.calendar:
            printer.add(fmt_datetime_relative(when, key.d_create))
            printer.add(fmt_datetime_relative(when, key.d_publish))
            printer.add(fmt_datetime_relative(when, key.d_active))
            printer.add(fmt_datetime_relative(when, key.d_inactive))
            printer.add(fmt_datetime_relative(when, key.d_delete))
        else:
            printer.add(fmt_next_change(when, key))
        if args.verify_ns:
            ksig = key.signer_id()
            key_results = key_collection.results[key.zone]
            # fill the table columns
            for ns in key_collection.contacted_servers():
                column = []
                if ns in key_results.ds:
                    # was this server queried for DS state at the delegation?
                    in_ds = key_results.ds[ns]
                    if isinstance(in_ds, Exception):
                        column.append(repr(in_ds)[:6])
                    elif ksig in in_ds:
                        column.append("DS")
                else:
                    # format (non-)presence information for DNSKEY + RRSIG at authoritative NS
                    in_dnskey = key_results.dnskey.get(ns, [])
                    in_rrsig = key_results.rrsig.get(ns, [])
                    # errors override any other input
                    if isinstance(in_dnskey, Exception):
                        column = [repr(in_dnskey)[:6]]
                    if isinstance(in_rrsig, Exception):
                        column = [repr(in_rrsig)[:6]]
                    if not column:
                        column.append(" P"[ksig in in_dnskey])
                        column.append(" S"[ksig in in_rrsig])
                printer.add(" ".join(column))
        printer.done()
        if args.print_record:
            align = printer.column_start("Algo")
            if key.type == "KSK":
                try:
                    print(key.ds_rr(indent=f"{'':{align}s}"))
                except:
                    pass
            print(key.dnskey_rr(indent=f"{'':{align}s}"))
    printer.done()
    print("")
    return 0


def main_archive(tool: DnsSec, args: argparse.Namespace) -> int:
    keys = tool.list_keys(args.ZONE, recursive=args.recurse)
    expired = []
    exp_ksk = 0
    key: KeyFile
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
        if key.path_state.exists():
            plan.append([key.type, key.path_state, tdir])
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
            src.rename(dst / src.name)
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
            new_key.set_perms()
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


def main_permissions(tool: DnsSec, args: argparse.Namespace) -> int:
    def expand_masks():
        for mask in args.FILES:
            for fil in tool.path.glob(mask):
                if fil.suffix == ".key":
                    yield fil
            if not mask.endswith("."):
                mask += "."
            for fil in tool.path.glob(mask + "key"):
                yield fil

    matched = sorted(set(expand_masks()))

    if args.dry_run:
        print("Would change:")
    for file in matched:
        kf = KeyFile(file)
        change = kf.set_perms(check_only=True)
        if change:
            print(kf.name)
            if not args.dry_run:
                kf.set_perms(check_only=False)

    return 0


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--dir", type=str,
                        help="directory containing key files")

    sp = parser.add_subparsers(metavar="COMMAND")
    sp.required = True

    p_list = sp.add_parser("list",
                           help="List currently present keys and their timing",
                           formatter_class=ParagraphFormatter)
    # selection options
    p_list.add_argument("ZONE", type=str,
                        help="DNS zone to work on")
    p_list.add_argument("-r", "--recurse", action="store_true", default=False,
                        help="Show key for all zones below the given one")
    p_list.add_argument("-s", "--state", action=MultipleEnumAction, metavar="STATE", suffix=True,
                        choices=["PUB", "ACT", "INAC", "DEL", "FUT"],
                        help="Filter keys by current state")
    p_list.add_argument("-t", "--type", action=MultipleEnumAction, choices=["ZSK", "KSK"],
                        help="Filter keys by type")
    # output options
    p_list.add_argument("-O", "--output", action=EnumAction, choices=["GRID", "TABLE", "JSON"], default="GRID",
                        help="Format output as table or JSON")
    p_list.add_argument("--when", default=None, type=parse_datetime, metavar="DATETIME",
                        help="When computing states, use DATETIME instead of current")
    p_list.add_argument("-o", "--sort", action=MultipleEnumAction, metavar="FIELD", suffix=True,
                        choices=["ZONE", "TYPE", "ALG", "ID", "STATE", "DATE", "HOST"],
                        help="Sort keys by attribute")
    p_list.add_argument("-c", "--calendar", action="store_true", default=False,
                        help="Show relative time to each state change (default: only timestamp of next change)")
    p_list.add_argument("-p", "--permissions", action="store_true", default=False,
                        help="Print asterisk for keys with bad permissions")
    # additional functions / checks
    p_list.add_argument("--print-record", action="store_true", default=False,
                        help="Output DNSKEY RR payload and DS record (for KSKs) in table")
    p_list.add_argument("--verify-ns", action="append", type=str, nargs="?", default=[], metavar="SERVER",
                        help="Query nameserver(s) for actually present keys. "
                             "If no specific server given, query all NS set for each zone.")
    p_list.add_argument("--resolver", type=str, metavar="ADDR", action=ResolverListAction,
                        help="Resolver(s) to use instead of system default, or the special keyword 'recurse' to switch"
                             " to an internal recursive resolver. Can be combined and given multiple times, unless 'recurse' is used.")
    pg_ip = p_list.add_mutually_exclusive_group()
    pg_ip.add_argument("-4", dest="ip", action="store_const", const=4)
    pg_ip.add_argument("-6", dest="ip", action="store_const", const=6, default=6,
                       help="Prefer IPv4 or IPv6 for communcation with nameservers (default: IPv6)")
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

    p_perms = sp.add_parser("permissions",
                            help="Fix file permissions")
    p_perms.add_argument("FILES", type=str, nargs="+",
                         help="File or shell pattern to match, excluding file extension")
    p_perms.add_argument("-n", "--dry-run", action="store_true", default=False,
                         help="Don't perform action, just show files that would be changed")
    p_perms.set_defaults(func=main_permissions)

    args = parser.parse_args()

    if args.dir:
        keydir = Path(args.dir)
        if not keydir.exists():
            raise IOError(f"Key directory '{args.dir}' not found!")
    else:
        keydir = Path.cwd()

    if "resolver" in args and args.resolver:
        has_rec = sum(r.upper() == "RECURSE" for r in args.resolver)
        if has_rec > 0:
            if has_rec != len(args.resolver):
                parser.error(f"Internal recursive resolver can not be combined with external resolvers")
            args.resolver = "RECURSE"

    if "ZONE" in args and args.ZONE:
        if not args.ZONE.endswith("."):
            args.ZONE += "."
            print(f"Zone is missing root label, assuming fully qualified: {args.ZONE}", file=sys.stderr)

    tool = DnsSec(keydir)

    return args.func(tool, args)


if __name__ == "__main__":
    sys.exit(main())
