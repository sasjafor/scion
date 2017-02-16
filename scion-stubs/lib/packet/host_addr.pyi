from lib.types import AddrType
from lib.packet.packet_base import Serializable
from typing import Optional


class HostAddrBase(Serializable):
    TYPE = None  # type: Optional[int]
    LEN = None  # type: Optional[int]


class HostAddrNone(HostAddrBase):  # pragma: no cover
    """
    Host "None" address. Used to indicate there's no address.
    """
    TYPE = AddrType.NONE
    LEN = 0


class HostAddrSVC(HostAddrBase):
    """
    Host "SVC" address. This is a pseudo- address type used for SCION services.
    """
    TYPE = AddrType.SVC
    LEN = 2
    NAME = "HostAddrSVC"
    MCAST = 0x8000