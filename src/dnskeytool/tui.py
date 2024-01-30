import argparse
import json
from typing import List, Any, Optional


def shortest_unique(*choices):
    def wrapped(func):
        def parser(inp: str):
            s = func(inp)
            # simple cases: not given or direct match?
            if s == "" or s in choices:
                return s
            # uniquely specified?
            matching = [c for c in choices if c.startswith(s)]
            if len(matching) == 1:
                return matching[0]
            raise ValueError(f"Ambiguous argument {s}, could mean one of {' '.join(matching)}")

        parser.CHOICES = choices
        return parser

    return wrapped


class SplitAppendArgs(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        oldlist = getattr(namespace, self.dest) or []
        newlist = [self.filter(value.strip()) for value in values.split(",")]
        setattr(namespace, self.dest, self.combine(oldlist, [arg for arg in newlist if arg is not None]))

    def filter(self, arg):
        return arg

    def combine(self, oldlist: List, newlist: List) -> List:
        return oldlist + newlist


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
        if self.state == "head":
            if w is None:
                w = len(val)
            head = self.get_formatted(val, f, align, w)
            self.current_row.append(head)
            self.column_meta.append({"width": len(head), "align": align, "name": val})
        elif self.state == "row":
            coli = len(self.current_row)
            w = self.column_meta[coli].get("width", 0)
            if not align:
                align = self.column_meta[coli].get("align", align)
            self.current_row.append(self.get_formatted(val, f, align, w))
        else:
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
        if self.state == "head":
            for meta in self.column_meta:
                meta["width"] = 0
        elif self.state == "done":
            print(json.dumps(self.obj, indent=2))
