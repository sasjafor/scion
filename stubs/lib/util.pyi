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