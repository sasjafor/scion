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
                Forall(self.contents(), lambda e: (e.State())))
               #Forall(self.contents(), lambda e: (e.State(), [[e in self.contents()]])))

    @Pure
    @ContractOnly
    def contents(self) -> Sequence[OpaqueField]:
        Requires(Acc(self._order) and Acc(self._labels))
        Requires(dict_pred(self._labels))
        Ensures(len(Result()) == self.__len__())

    @Pure
    @ContractOnly
    def __len__(self) -> int:
        Requires(Acc(self._labels))
        Requires(dict_pred(self._labels))
        Ensures(Result() >= 0)


    @Pure
    @ContractOnly
    def get_by_idx(self, idx: int) -> OpaqueField:
        Requires(self.State())
        Requires(idx >= 0 and idx < Unfolding(self.State(), len(self)))
        Ensures(Result() is Unfolding(self.State(), self.contents()[idx]))
        Ensures(Result() in Unfolding(self.State(), self.contents()))
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

    def calc_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> None:
        ...

    def set_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bytes:
        ...

    @Pure
    @ContractOnly
    def verify_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bool:  # pragma: no cover
        Requires(Implies(prev_hof is not None, Acc(prev_hof.State(), 1/1000)))

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