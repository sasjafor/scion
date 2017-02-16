from typing import Union



def PBKDF2(password: Union[int, str, bytes], salt:bytes, dkLen:int =16, count:int=1000) -> bytes:
    ...