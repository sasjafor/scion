from lib.types import AddrType
from typing import Optional, Tuple


class Socket:
    pass




class UDPSocket(Socket):
    def __init__(self, bind: Optional[Tuple[str, int]] = None, addr_type: int=AddrType.IPV6,
                 reuse: bool=False) -> None:
        ...

    def send(self, data: bytes, dst: Tuple[str, int]=None) -> bool:
        ...

class ReliableSocket(Socket):
    pass


class SocketMgr(object):
    def add(self, sock: UDPSocket, callback: object) -> None:
        ...


class TCPSocketWrapper(object):
    """
    Base class for accepted and connected TCP sockets used by SCION services.
    """
    RECV_SIZE = 8092