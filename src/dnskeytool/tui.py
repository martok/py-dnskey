import argparse
import dataclasses
import json
from enum import Flag
from operator import attrgetter
from typing import List, Any, Optional, Union, Callable


class ParagraphFormatter(argparse.HelpFormatter):
    def _split_lines(self, text, width):
        res = []
        for par in text.splitlines():
            res.extend(argparse.HelpFormatter._split_lines(self, par, width))
        return res


class ListAppendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        oldlist = getattr(namespace, self.dest) or []
        newlist = [self.filter(value.strip()) for value in values.split(",")]
        setattr(namespace, self.dest, self.combine(oldlist, [arg for arg in newlist if arg is not None]))

    def filter(self, arg):
        return arg

    def combine(self, oldlist: List, newlist: List) -> List:
        return oldlist + newlist


class EnumAction(argparse.Action):
    def __init__(self, option_strings, dest, required=False, help=None, metavar=None,
                 choices=None, default=None, case_sensitive=False, allow_abbrev=True):
        if not choices:
            choices = []
        if not case_sensitive:
            choices = [str(c).upper() for c in choices]
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=None,
            required=required,
            help=help,
            metavar=metavar,
            choices=None)
        # rename this because otherwise ArgumentParser._check_value would use it
        self.values = choices
        self.case_sensitive = case_sensitive
        self.allow_abbrev = allow_abbrev
        if not metavar:
            self.metavar = self.choices_str()
        else:
            self.help = "\n".join([self.help, "Values: " + self.choices_str()])
        if default is not None:
            self.default = self.parse(default)

    def __call__(self, parser, namespace, values, option_string=None):
        stored = getattr(namespace, self.dest, None)
        try:
            value = self.parse(values)
            setattr(namespace, self.dest, value)
        except (TypeError, ValueError):
            args = {'type': self.__class__.__name__, 'value': values}
            msg = argparse._('invalid %(type)s value: %(value)r')
            raise argparse.ArgumentError(self, msg % args)

    def choices_str(self):
        choice_strs = [str(choice) for choice in self.values]
        return "{%s}" % ",".join(choice_strs)

    def parse(self, arg_str: str):
        split = self.split_values(arg_str)
        parsed = self.parse_values(split)
        self.check_parsed(parsed)
        return self.create_type(parsed)

    def split_values(self, values: str) -> List[str]:
        return [values]

    def parse_values(self, values: List[str]):
        return [self.matched_value(v) for v in values]

    def matched_value(self, s: str):
        if not self.case_sensitive:
            s = s.upper()
        # simple cases: not given or direct match?
        if s == "" or s in self.values:
            return s
        if self.allow_abbrev:
            # uniquely specified?
            matching = [c for c in self.values if c.startswith(s)]
            if not matching:
                raise ValueError(f"Unknown value {s}")
            if len(matching) == 1:
                return matching[0]
            raise ValueError(f"Ambiguous argument {s}, could mean one of {' '.join(matching)}")
        raise ValueError(f"Invalid argument {s}")

    def check_parsed(self, parsed):
        if len(parsed) != 1:
            raise ValueError(f"Expected a single value of {self.choices_str()}")

    def create_type(self, parsed):
        return parsed[0]


FilterKeyFun = Callable[[Any], Union[str, Flag]]


@dataclasses.dataclass
class MultipleEnumType:
    values: List[str]
    suffix: List[bool]

    def as_sets(self):
        pos = set()
        neg = set()
        for v, s in zip(self.values, self.suffix):
            if s:
                neg.add(v)
            else:
                pos.add(v)
        return pos, neg

    def as_filter(self, iterable, key=Union[str, FilterKeyFun]):
        if isinstance(key, str):
            key = attrgetter(key)
        pos, neg = self.as_sets()

        def comparator(x):
            # as set operations, the rule is: accept iff some element of k is in pos and no element of k is in neg
            # pos and neg can not both be empty, therefore one of the checks always does something.
            k = key(x)
            check = set()
            if isinstance(k, Flag):
                check.update(f.name for f in k)
            else:
                check.add(k)
            return (check.isdisjoint(neg)) and (not pos or not check.isdisjoint(pos))

        return filter(comparator, iterable)

    def as_multi_sorter(self, iterable, key=None):
        if key is None:
            key = attrgetter
        for fieldname, desc in reversed(list(zip(self.values, self.suffix))):
            keyfun = key(fieldname)
            iterable = sorted(iterable, key=keyfun, reverse=desc)
        return iterable


class MultipleEnumAction(EnumAction):
    def __init__(self, option_strings, dest, required=False, help=None, metavar=None, choices=None, default=None,
                 case_sensitive=False, allow_abbrev=True, suffix=None):
        super().__init__(option_strings, dest, required, help, metavar, choices, default, case_sensitive, allow_abbrev)
        if suffix:
            if isinstance(suffix, str):
                self.suffix = suffix
            else:
                self.suffix = "-"
        else:
            self.suffix = ""

    def split_values(self, values: str) -> List[str]:
        return values.split(",")

    def matched_value(self, s: str):
        suffix = False
        if self.suffix:
            if s.endswith(self.suffix):
                s = s[:-len(self.suffix)]
                suffix = True
        return super().matched_value(s), suffix

    def check_parsed(self, parsed):
        if len(set(parsed)) != len(parsed):
            raise ValueError(f"Duplicated values")

    def create_type(self, parsed):
        values, suffix = zip(*parsed)
        return MultipleEnumType(values=values, suffix=suffix)


class TablePrinterBase:
    def __init__(self) -> None:
        self.column_meta: List[dict] = []
        self.state = "empty"
        self.current_row: List[str] = []

    def get_formatted(self, val: str, fmt: str, align: str, width: int):
        return format(val, align + str(width) + fmt)

    def column_start(self, name: str) -> int:
        res = 0
        for meta in self.column_meta:
            if meta.get("name") == name:
                return res
            res += meta.get("width") + 1
        return 0

    def emit_row(self):
        print(*self.current_row, flush=True)

    def start_header(self):
        if self.state != "empty":
            raise ValueError("Can not start header at this point")
        self.current_row = []
        self.state = "head"

    def start_row(self):
        if self.state not in ["head", "row"]:
            raise ValueError("Can not start row at this point")
        self.current_row = []
        self.state = "row"

    def done(self):
        if self.current_row:
            self.emit_row()
        else:
            self.state = "done"
        self.current_row = []

    def add(self, val: Any, *,
                  f="s", align="", w: Optional[int] = None):
        if not isinstance(val, str):
            val = str(val)
        match self.state:
            case "head":
                if w is None:
                    w = len(val)
                head = self.get_formatted(val, f, align, w)
                self.current_row.append(head)
                self.column_meta.append({"width": len(head), "align": align, "name": val})
            case "row":
                coli = len(self.current_row)
                w = self.column_meta[coli].get("width", 0)
                if not align:
                    align = self.column_meta[coli].get("align", align)
                self.current_row.append(self.get_formatted(val, f, align, w))
            case _:
                raise ValueError("Invalid state")


class TablePrinter(TablePrinterBase):
    def __init__(self) -> None:
        super().__init__()
        self.with_grid = True

    def emit_row(self):
        if self.with_grid:
            print(*self.current_row, sep="|")
            if self.state == "head":
                delim = []
                for meta in self.column_meta:
                    delim.append("-" * meta.get("width", 1))
                print("+".join(delim), flush=True)
        else:
            super().emit_row()


class JSONPrinter(TablePrinterBase):
    def __init__(self) -> None:
        super().__init__()
        self.obj = []

    def column_start(self, name: str) -> int:
        return 0

    def emit_row(self):
        if self.state == "row":
            obj = dict()
            for val, meta in zip(self.current_row, self.column_meta):
                nam = meta["name"]
                if nam in obj:
                    for i in range(100):
                        if f"{nam}_{i}" not in obj:
                            nam = f"{nam}_{i}"
                            break
                obj[nam] = val
            self.obj.append(obj)

    def done(self):
        super().done()
        match self.state:
            case "head":
                for meta in self.column_meta:
                    meta["width"] = 0
            case "done":
                print(json.dumps(self.obj, indent=2))
