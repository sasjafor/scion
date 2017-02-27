from typing import Generic, TypeVar, Dict


T = TypeVar('T')
V = TypeVar('V')

class ExpiringDict(Generic[T, V], Dict[T, V]):
    def __init__(self, max_len: int, max_age_seconds: int) -> None:
        ...
