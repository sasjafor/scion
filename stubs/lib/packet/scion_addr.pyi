from typing import Optional


class ISD_AS:
    def __init__(self, raw: Optional[str] = None) -> None: ...
    def to_int(self) -> int: ...


class SCIONAddr(object):
    pass