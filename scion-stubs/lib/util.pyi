from typing import Dict, Optional
from py2viper_contracts.contracts import *

class SCIONTime(object):
    #_custom_time = None  # type: None

    @classmethod
    def get_time(cls) -> int: ...

    @classmethod
    def set_time_method(cls, method:Optional[object]=None) -> None: ...

def load_yaml_file(file_path: str) -> Dict[str, object]:
    Ensures(Acc(dict_pred(Result())))
    ...

class Raw(object):
    pass


def sleep_interval(start: float, interval: float, desc: str, quiet: bool =False) -> None:
    ...


def hex_str(raw: Raw) -> str:
    ...