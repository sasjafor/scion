from typing import Generic, TypeVar

T = TypeVar('T')

class Queue:


    def __init__(self, maxsize: int=0) -> None:
        ...