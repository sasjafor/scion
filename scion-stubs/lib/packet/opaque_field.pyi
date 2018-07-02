from nagini_contracts.obligations import MustTerminate

from lib.errors import SCIONIndexError
from lib.packet.packet_base import Serializable
from lib.defines import OPAQUE_FIELD_LEN
from lib.util import Raw
from typing import Dict, List, Sized, Tuple
from nagini_contracts.contracts import Acc, ContractOnly, Ensures, Forall, Implies, Predicate, Pure, Requires, Result, \
    Sequence, Unfolding, Assert, dict_pred


class OpaqueField(Serializable):
    LEN = OPAQUE_FIELD_LEN

    @Predicate
    def State(self) -> bool:
        return True


class OpaqueFieldList(Sized):
    def __init__(self, order: Tuple[str, ...]) -> None:  # pragma: no cover
        """
        :param list order:
            A list of tokens that define the order of the opaque field labels.
            E.g. ``[UP_IOF, UP_HOFS]`` defines that the up-segment info opaque
            field comes before the up-segment hop opaque fields.
        """
        self._order = order
        self._labels = {}  # type: Dict[str, List[OpaqueField]]
        for label in order:
            self._labels[label] = []

    @Predicate
    def State(self) -> bool:
        return (Acc(self._order) and Acc(self._labels) and Acc(dict_pred(self._labels)) and
                Forall(self.contents(), lambda e: (e.State(), [[e in self.contents()]])))

    @Pure
    @ContractOnly
    def contents(self) -> Sequence[OpaqueField]:
        Requires(Acc(self._order, 1/10) and Acc(self._labels, 1/10))
        Requires(Acc(dict_pred(self._labels), 1/10))
        Ensures(len(Result()) == self.__len__())

    @Pure
    @ContractOnly
    def get_hofs_in_segment(self, iof: InfoOpaqueField) -> Sequence[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        # Helper method for contracts that returns the hop fields in a segment for a given InfoOpaqueField

    @Pure
    @ContractOnly
    def __len__(self) -> int:
        Requires(Acc(self._labels, 1/10))
        Requires(Acc(dict_pred(self._labels), 1/10))
        Ensures(Result() >= 0)

    @Pure
    @ContractOnly
    def count(self, label: str) -> int:
        Requires(Acc(self.State(), 1/10))

    @Pure
    @ContractOnly
    def get_label_by_idx(self, idx: int) -> str:
        Requires(Acc(self.State(), 1/10))

    @Pure
    @ContractOnly
    def get_by_idx(self, idx: int) -> OpaqueField:
        Requires(Acc(self.State(), 1/10))
        Requires(idx >= 0 and idx < self.get_len())
        Ensures(Result() is Unfolding(Acc(self.State(), 1/10), self.contents()[idx]))
        Ensures(Result() in Unfolding(Acc(self.State(), 1/10), self.contents()))
        # """
        # Get an OF by index. The index follows the order supplied when the
        # :class:`OpaqueFieldList` object was created.
        #
        # :param int idx: The index to fetch.
        # :returns: The OF at that index.
        # :rtype: :class:`OpaqueField`
        # :raises:
        #     SCIONIndexError: if the index is negative, or too large.
        # """
        # if idx < 0:
        #     raise SCIONIndexError("Requested OF index (%d) is negative" % idx)
        # offset = idx
        # for label in self._order:
        #     group = self._labels[label]
        #     if offset < len(group):
        #         return group[offset]
        #     offset -= len(group)
        # raise SCIONIndexError("Requested OF index (%d) is out of range (max %d)"
        #                       % (idx, len(self) - 1))

    """
    Start of helper functions for performance
    """

    @Pure
    def get_len(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), len(self))

    @Pure
    def get_contents(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.contents())


class HopOpaqueField(OpaqueField):
    NAME = "HopOpaqueField"
    MAC_LEN = 3  # MAC length in bytes.
    MAC_BLOCK_LEN = 16

    def __init__(self, raw: Raw=None) -> None:  # pragma: no cover
        self.xover = False
        self.verify_only = False
        self.forward_only = False
        self.recurse = False
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = bytes(self.MAC_LEN)

    @Pure
    @ContractOnly
    def calc_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bytes:
        Requires(Acc(self.State(), 1/10))
        Requires(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/10)))
        # Requires(MustTerminate(1))
        # Ensures(Acc(self.State(), 1/10))
        # Ensures(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/10)))
        ...

    def set_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> None:
        ...

    @Pure
    def verify_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bool:  # pragma: no cover
        Requires(Acc(self.State(), 1/10))
        Requires(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/10)))
        # Requires(MustTerminate(2))
        # Ensures(Acc(self.State(), 1/10))
        # Ensures(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/10)))
        return self.get_mac() == self.calc_mac(key, ts, prev_hof)

    @classmethod
    def from_values(cls, exp_time: int, ingress_if: int=0, egress_if: int=0,
                    mac: bytes=None, xover: bool=False, verify_only: bool=False,
                    forward_only: bool=False, recurse: bool=False) -> 'HopOpaqueField':
        ...

    @Predicate
    def State(self) -> bool:
        return (Acc(self.xover) and
                Acc(self.verify_only) and
                Acc(self.forward_only) and
                Acc(self.recurse) and
                Acc(self.exp_time) and
                Acc(self.ingress_if) and
                Acc(self.egress_if) and
                Acc(self.mac))

    """
    Start of helper functions for performance
    """

    @Pure
    def get_xover(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.xover)

    @Pure
    def get_verify_only(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.verify_only)

    @Pure
    def get_forward_only(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.forward_only)

    @Pure
    def get_exp_time(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.exp_time)

    @Pure
    def get_egress_if(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.egress_if)

    @Pure
    def get_ingress_if(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.ingress_if)

    @Pure
    def get_mac(self) -> bytes:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.mac)

class InfoOpaqueField(OpaqueField):
    def __init__(self) -> None:  # pragma: no cover
        self.up_flag = False
        self.shortcut = False
        self.peer = False
        self.timestamp = 0
        self.isd = 0
        self.hops = 0

    @Predicate
    def State(self) -> bool:
        return (Acc(self.up_flag) and
                Acc(self.shortcut) and
                Acc(self.peer) and
                Acc(self.timestamp) and
                Acc(self.isd) and
                Acc(self.hops))

    @Pure
    def get_up_flag(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.up_flag)

    @Pure
    def get_shortcut(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.shortcut)

    @Pure
    def get_peer(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.peer)

    @Pure
    def get_hops(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.hops)

    @Pure
    def get_timestamp(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.timestamp)
