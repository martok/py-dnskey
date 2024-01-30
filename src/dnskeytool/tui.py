import argparse
from typing import List


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
