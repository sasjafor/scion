from typing import Generic, TypeVar

T = TypeVar('T')

class Queue:


    def __init__(self, maxsize: int=0) -> None:
        ...

    def put(self, item: object, block: bool=True, timeout:float=None) -> None:
        ...

    def get_nowait(self) -> object:
        ...