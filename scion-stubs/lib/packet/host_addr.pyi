from lib.errors import SCIONBaseError
from lib.types import AddrType
from lib.packet.packet_base import Serializable
from typing import Optional
from nagini_contracts.contracts import ContractOnly, Pure

# class HostAddrInvalidType(SCIONBaseError):
#     """
#     HostAddr type is invalid.
#     """
#     pass

class HostAddrBase(Serializable):
    TYPE = None  # type: Optional[int]
    LEN = None  # type: Optional[int]

    def __init__(self, addr: HostAddrBase, raw: bool=True) -> None:  # pragma: no cover
        """
        :param addr: Address to parse/store.
        :param bool raw: Does the address need to be parsed?
        """
        self.addr = None # type: Optional[HostAddrBase]
        if raw:
            self._parse(addr)
        else:
            self.addr = addr

    @Pure
    @ContractOnly
    def __str__(self) -> str:
        ...

    def _parse(self, addr: HostAddrBase) -> None:
        ...


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


IPV4LENGTH = 32
IPV6LENGTH = 128


class HostAddrIPv4(HostAddrBase):
    """
    Host IPv4 address.
    """
    TYPE = AddrType.IPV4
    LEN = IPV4LENGTH // 8


class HostAddrIPv6(HostAddrBase):
    """
    Host IPv6 address.
    """
    TYPE = AddrType.IPV6
    LEN = IPV6LENGTH // 8

# _map = {
#     # By type
#     AddrType.NONE: HostAddrNone,
#     AddrType.IPV4: HostAddrIPv4,
#     AddrType.IPV6: HostAddrIPv6,
#     AddrType.SVC: HostAddrSVC,
#     # By name
#     "NONE": HostAddrNone,
#     "IPV4": HostAddrIPv4,
#     "IPV6": HostAddrIPv6,
#     "SVC": HostAddrSVC,
# }

# def haddr_get_type(type_):  # pragma: no cover
#     """
#     Look up host address class by type.
#
#     :param type\_: host address type. E.g. ``1`` or ``"IPV4"``.
#     :type type\_: int or string
#     """
#     try:
#         return _map[type_]
#     except KeyError:
#         raise HostAddrInvalidType("Unknown host addr type '%s'" %
#                                   type_) from None
