from nagini_contracts.obligations import MustTerminate

from lib.packet.host_addr import HostAddrBase
from typing import Optional, cast
from nagini_contracts.contracts import *

from lib.packet.packet_base import Serializable


class ISD_AS(Serializable):
    LEN = 4

    def __init__(self, raw: Optional[str] = None) -> None:
        self._isd = 0
        self._as = 0

    def to_int(self) -> int: ...

    @Pure
    def __eq__(self, other: object) -> bool:  # pragma: no cover
        Requires(Acc(self.State(), 1/10))
        Requires(Implies(isinstance(other, ISD_AS), Acc(cast(ISD_AS, other).State(), 1/10)))
        if not isinstance(other, ISD_AS):
            return False
        return self.get_isd() == other.get_isd() and self.get_as() == other.get_as()

    @Predicate
    def State(self) -> bool:
        return Acc(self._isd) and Acc(self._as)

    """
    Start of Performance helper functions
    """

    @Pure
    def get_isd(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self._isd)

    @Pure
    def get_as(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self._as)

class SCIONAddr(object):
    def __init__(self) -> None:  # pragma: no cover
        self.isd_as = None  # type: Optional[ISD_AS]
        self.host = None  # type: Optional[HostAddrBase]

    @Predicate
    def State(self) -> bool:
        return (Acc(self.isd_as) and Implies(self.isd_as is not None, self.isd_as.State()) and
                Acc(self.host) and Implies(self.host is not None, self.host.State()))

    @Pure
    def matches(self, raw: bytes, offset: int) -> bool:
        return True

    @classmethod
    def from_values(cls, isd_as: Optional[ISD_AS], host: Optional[HostAddrBase]) -> 'SCIONAddr':  # pragma: no cover
        Requires(MustTerminate(1))
        ...

    # @classmethod
    # def calc_len(cls, type_):  # pragma: no cover
    #     class_ = haddr_get_type(type_)
    #     return ISD_AS.LEN + class_.LEN

    def pack(self) -> bytes:  # pragma: no cover
        ...