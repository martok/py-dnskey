import itertools
from typing import TypeVar, Iterable, Callable, Dict, List, Tuple

T1 = TypeVar("T1")
T2 = TypeVar("T2")


def groupby_freeze(iterable: Iterable[T1], key: Callable[[T1], T2]) -> Dict[T2, List[T1]]:
    return {k: list(g) for k, g in itertools.groupby(iterable, key)}


def partition(test: Callable[[T1], bool], iterable: Iterable[T1]) -> Tuple[List[T1], List[T1]]:
    a = []
    b = []
    for o in iterable:
        if test(o):
            a.append(o)
        else:
            b.append(o)
    return a, b
