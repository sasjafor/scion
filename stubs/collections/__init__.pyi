from typing import Generic, TypeVar, Dict, Type


T = TypeVar('T')
V = TypeVar('V')

def defaultdict(t: T, v: V) -> Dict[T, V]:
    ...