

def error(msg: str, a: object, b: object) -> None: ...

def warning(msg: str, a: object, b: object) -> None: ...

def debug(msg: str, a: object, b: object) -> None: ...

def info(msg: str, a: object, b: object) -> None: ...

def critical(msg: str, a: object, b: object) -> None: ...


CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0