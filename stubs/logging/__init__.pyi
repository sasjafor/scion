from nagini_contracts.contracts import Requires
from nagini_contracts.obligations import MustTerminate


def error(msg: str, *args: object) -> None:
    Requires(MustTerminate(1))
    ...

def warning(msg: str, *args: object) -> None: ...

def debug(msg: str, *args: object) -> None:
    Requires(MustTerminate(1))
    ...

def info(msg: str, *args: object) -> None:
    Requires(MustTerminate(1))
    ...


CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0