from typing import Generic, TypeVar, Dict


T = TypeVar('T')
V = TypeVar('V')

def ExpiringDict(max_len: int, max_age_seconds: int) -> Dict[T, V]:
    ...
