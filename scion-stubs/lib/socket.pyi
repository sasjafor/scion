from lib.types import AddrType
from typing import Optional, Tuple
from nagini_contracts.contracts import *
from nagini_contracts.io_builtins import Place, token, IOOperation, IOExists1, Terminates

class Socket:
    pass


@IOOperation
def udp_send(t_pre: Place, data: bytes, dst_addr: str, dst_port: int, t_post: Place = Result()) -> bool:
    Terminates(True)

class UDPSocket(Socket):
    def __init__(self, bind: Optional[Tuple[str, int]] = None, addr_type: int=AddrType.IPV6,
                 reuse: bool=False) -> None:
        ...

    def send(self, t: Place, data: bytes, dst: Tuple[str, int]=None) -> Tuple[bool, Place]:
        IOExists1(Place)(lambda t2: (
            Requires(dst is not None and token(t) and udp_send(t, data, dst[0], dst[1], t2)),
            Ensures(Result()[1] is t2 and token(t2))
        ))
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