from py2viper_contracts.contracts import *

@Pure
def dirname(p: str) -> str: ...

@Pure
def abspath(p: str) -> str: ...

def join(path: str, *paths: str) -> str:
    ...