from typing import Generic, TypeVar, Dict, Type


T = TypeVar('T')
V = TypeVar('V')

class defaultdict(Generic[T, V], Dict[T, V]):
    def __init__(self, df: Type[V]) -> None:
        ...