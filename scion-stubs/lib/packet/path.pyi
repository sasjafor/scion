from nagini_contracts.obligations import MustTerminate

from lib.defines import EXP_TIME_UNIT
from lib.packet.packet_base import Serializable
from lib.packet.opaque_field import OpaqueField, InfoOpaqueField, HopOpaqueField, OpaqueFieldList
from lib.packet.pcb import ASMarking
from lib.util import Raw, SCIONTime
from typing import cast, Optional, Sized, List, Tuple
from nagini_contracts.contracts import *

class SCIONPath(Serializable, Sized):
    NAME = "SCIONPath"
    A_IOF = "A_segment_iof"
    A_HOFS = "A_segment_hofs"
    B_IOF = "B_segment_iof"
    B_HOFS = "B_segment_hofs"
    C_IOF = "C_segment_iof"
    C_HOFS = "C_segment_hofs"
    OF_ORDER = A_IOF, A_HOFS, B_IOF, B_HOFS, C_IOF, C_HOFS
    IOF_LABELS = A_IOF, B_IOF, C_IOF
    HOF_LABELS = A_HOFS, B_HOFS, C_HOFS

    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        self._ofs = OpaqueFieldList(SCIONPath.OF_ORDER) # type: OpaqueFieldList
        self._iof_idx = None  # type: Optional[int]
        self._hof_idx = None  # type: Optional[int]
        self.interfaces = []  # type: List[Tuple[ASMarking, int]]
        self.mtu = None  # type: Optional[int]

    @Predicate
    def State(self) -> bool:
        """
        State of SCIONPath
        First comes the general part that holds for any instance of a path.
        The second part only holds for the specific case where there is one
        up segment in the path and there is no peering. It is needed for
        guaranteeing that get_hof_ver returns an object of type HopOpaqueField.
        The third part is also only for the specific case. It is needed, because
        with only one segment, we can't switch to a next segment in inc_hof_idx.
        """
        return (# First part
                Acc(self._ofs) and self._ofs.State() and
                Acc(self._hof_idx) and
                Acc(self._iof_idx) and
                Acc(self.interfaces) and Acc(list_pred(self.interfaces)) and
                Acc(self.mtu) and
                Implies(self._hof_idx is not None,
                        self._hof_idx >= 0 and self._hof_idx < self.state_get_ofs_len() and
                        isinstance(self._ofs.get_by_idx(self._hof_idx), HopOpaqueField)) and
                Implies(self._iof_idx is not None,
                        self._iof_idx >= 0 and self._iof_idx < self.state_get_ofs_len() and
                        isinstance(self._ofs.get_by_idx(self._iof_idx), InfoOpaqueField)) and
                # Start of the second part
                Implies(self._hof_idx is not None and
                        self._iof_idx is not None,
                        Let(cast(InfoOpaqueField, self._ofs.get_by_idx(self._iof_idx)), bool, lambda iof:
                            not self._ofs.get_iof_peer(iof) and self._ofs.get_iof_up_flag(iof) and
                            Implies((Let(cast(HopOpaqueField, self._ofs.get_by_idx(self._hof_idx)), bool, lambda hof:
                                        not self._ofs.get_hof_xover(hof) or
                                        self._ofs.get_iof_shortcut(iof)
                                        ) and
                                     (self._hof_idx != self._iof_idx + self._ofs.get_iof_hops(iof))),
                                    self._hof_idx + 1 < self.state_get_ofs_len() and
                                    isinstance(self._ofs.get_by_idx(self._hof_idx + 1), HopOpaqueField) and
                                    self._ofs.get_by_idx(self._hof_idx + 1) is not self._ofs.get_by_idx(self._hof_idx)
                                    )
                            )
                        ) and
                # Start of the third part
                Implies(self._hof_idx is not None and
                        self._iof_idx is not None and
                        self._hof_idx < self.state_get_ofs_len() - 1,
                        self._hof_idx + 1 < self.state_get_ofs_len() and
                        isinstance(self._ofs.get_by_idx(self._hof_idx + 1), HopOpaqueField) and
                        Let(cast(InfoOpaqueField, self._ofs.get_by_idx(self._iof_idx)), bool, lambda iof:
                            self._hof_idx - self._iof_idx <= self._ofs.get_iof_hops(iof)
                            )
                        ) and
                # needed for a valid packet
                self._hof_idx is not None and
                self._iof_idx is not None and
                Let(cast(InfoOpaqueField, self._ofs.get_by_idx(self._iof_idx)), bool, lambda iof:
                    self.get_iof_hops_1(iof) >= 0 and self._iof_idx + self.get_iof_hops_1(iof) < self.state_get_ofs_len()
                    )
                )

    @Pure
    def matches(self, raw: bytes, offset: int) -> bool:
        return True

    @Pure
    def get_iof(self) -> Optional[InfoOpaqueField]:  # pragma: no cover
        Requires(Acc(self.State(), 1/20))
        Ensures(Implies(self.get_iof_idx() is not None, Result() is not None))
        Ensures(Implies(Result() is not None, Result() in self.get_ofs_contents()))
        idx = self.get_iof_idx()
        if idx is None:
            return None
        return cast(InfoOpaqueField, Unfolding(Acc(self.State(), 1/20), self._ofs.get_by_idx(idx)))

    @Pure
    def get_hof(self) -> Optional[HopOpaqueField]:  # pragma: no cover
        Requires(Acc(self.State(), 1/10))
        Ensures(Implies(self.get_hof_idx() is not None, Result() is not None))
        Ensures(Implies(Result() is not None, Result() in self.get_ofs_contents()))
        idx = self.get_hof_idx()
        if idx is None:
            return None
        return cast(HopOpaqueField, Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(idx)))

    def get_hof_ver(self, ingress: bool =True) -> Optional[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Requires(Implies(not ingress,
                         self.get_hof_idx() + 1 < self.get_ofs_len() and
                         isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 1), HopOpaqueField) and
                         self.ofs_get_by_idx(self.get_hof_idx() + 1) is not self.ofs_get_by_idx(self.get_hof_idx())
                         )
                 )
        Requires(MustTerminate(3))
        Ensures(Acc(self.State(), 1/10))
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        Ensures(Implies(Result() is not None, Result() in self.get_ofs_contents()))
        Ensures(Implies(Result() is not None, Result() is not self.get_hof()))
        Ensures(Result() is self.get_hof_ver_pure())
        """Return the :any:`HopOpaqueField` needed to verify the current HOF."""
        iof = self.get_iof()
        hof = self.get_hof()
        if not self.get_hof_xover(hof) or (self.get_iof_shortcut(iof) and not self.get_iof_peer(iof)):
            # For normal hops on any type of segment, or cross-over hops on
            # non-peer shortcut hops, just use next/prev HOF.
            return self._get_hof_ver_normal(iof)
        iof_peer = self.get_iof_peer(iof)
        iof_up_flag = self.get_iof_up_flag(iof)
        if iof_peer:
            # Peer shortcut paths have two extra HOFs; 1 for the peering
            # interface, and another from the upstream interface, used for
            # verification only.
            if ingress:
                if iof_up_flag:
                    offset = 2  ## type: Optional[int]
                else:
                    offset = 1
            else:
                if iof_up_flag:
                    offset = -1
                else:
                    offset = -2
        else:
            # Non-peer shortcut paths have an extra HOF above the last hop, used
            # for verification of the last hop in that segment.
            if ingress:
                if iof_up_flag:
                    offset = None
                else:
                    offset = -1
            else:
                if iof_up_flag:
                    offset = 1
                else:
                    offset = None
        # Map the local direction of travel and the IOF up flag to the required
        # offset of the verification HOF (or None, if there's no relevant HOF).
        if not isinstance(offset, int):
            return None
        return cast(HopOpaqueField, Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(self._hof_idx + offset)))

    def _get_hof_ver_normal(self, iof: InfoOpaqueField) -> Optional[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(iof in self.get_ofs_contents())
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Requires(not self.get_hof_xover(self.get_hof()) or self.get_iof_shortcut(iof))
        Requires(Unfolding(Acc(self.State(), 1/10), iof is self._ofs.get_by_idx(self._iof_idx)))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        Ensures(Implies(Result() is not None, Result() in self.get_ofs_contents()))
        Ensures(Implies(Result() is not None, Result() is not self.get_hof()))
        # Requires iof in bla
        # If this is the last hop of an Up path, or the first hop of a Down
        # path, there's no previous HOF to verify against.
        if (self.get_iof_up_flag(iof) and self.get_hof_idx() == self.get_iof_idx() + self.get_iof_hops(iof)) or (
                not self.get_iof_up_flag(iof) and self.get_hof_idx() == self.get_iof_idx() + 1):
            return None
        # Otherwise use the next/prev HOF based on the up flag.
        offset = 1 if self.get_iof_up_flag(iof) else -1
        return cast(HopOpaqueField, self.ofs_get_by_idx(self.get_hof_idx() + offset))

    @Pure
    def is_on_last_segment(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_hof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        label = self.get_ofs_label_by_idx()
        if label == self.A_HOFS:
            return self.get_ofs_count(self.B_HOFS) == 0
        elif label == self.B_HOFS:
            return self.get_ofs_count(self.C_HOFS) == 0
        else:
            return True

    @Pure
    def get_fwd_if(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        """Return the interface to forward the current packet to."""
        if not self.get_ofs_len():
            return 0
        iof = self.get_iof()
        hof = self.get_hof()
        if self.get_iof_up_flag(iof):
            return self.get_hof_ingress_if(hof)
        return self.get_hof_egress_if(hof)

    def inc_hof_idx(self) -> bool:
        Requires(Acc(self.State()))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Requires(self.get_hof_idx() < self.get_ofs_len() - 1)
        Requires(Let(cast(HopOpaqueField, Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(self.get_hof_idx() + 1))), bool, lambda hof:
                    not self.get_hof_verify_only(hof)))
        Requires(self.get_hof_idx() - self.get_iof_idx() < self.get_iof_hops(cast(InfoOpaqueField, self.ofs_get_by_idx(self.get_iof_idx()))))
        Requires(Let(cast(InfoOpaqueField, self.ofs_get_by_idx(self.get_iof_idx())), bool, lambda iof:
                        Implies((Let(cast(HopOpaqueField, self.ofs_get_by_idx(self.get_hof_idx() + 1)), bool, lambda hof:
                                    not self.get_hof_xover(hof) or
                                    self.get_iof_shortcut(iof)
                                    ) and
                                    (self.get_hof_idx() != self.get_iof_idx() + self.get_iof_hops(iof))),
                                self.get_hof_idx() + 2 < self.get_ofs_len() and
                                isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 2), HopOpaqueField) and
                                self.ofs_get_by_idx(self.get_hof_idx() + 2) is not self.ofs_get_by_idx(self.get_hof_idx() + 1)
                                )
                    )
                )
        Requires(Implies(self.get_hof_idx() < self.get_ofs_len() - 2, isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 2), HopOpaqueField)))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State()))
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        Ensures(self.get_ofs_contents() is Old(self.get_ofs_contents()))
        Ensures(self.get_iof_idx() == Old(self.get_iof_idx()))
        Ensures(Result() is False)
        """
        Increment the HOF idx to next routing HOF.

        Skip VERIFY_ONLY HOFs, as they are not used for routing.
        Also detect when there are no HOFs left in the current segment, and
        switch to the next segment, before restarting.
        """
        iof_idx = self.get_iof_idx()
        hof_idx = self.get_hof_idx()
        iof = self.get_iof()
        skipped_verify_only = False
        while True:
            Invariant(Acc(self.State()))
            Invariant(self.get_iof_idx() is not None)
            Invariant(self.get_hof_idx() is not None)
            Invariant(self.get_iof_idx() == iof_idx)
            Invariant(self.ofs_get_by_idx(self.get_iof_idx()) is iof)
            Invariant(iof is not None)
            Invariant(iof in self.get_ofs_contents())
            Invariant(isinstance(self.ofs_get_by_idx(self.get_iof_idx()), InfoOpaqueField))
            Invariant(self.get_hof_idx() < self.get_ofs_len() - 1)
            Invariant(isinstance(self.ofs_get_by_idx(self.get_hof_idx()), HopOpaqueField))
            Invariant(isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 1), HopOpaqueField))
            Invariant(not self.get_hof_verify_only(cast(HopOpaqueField, self.ofs_get_by_idx(self.get_hof_idx() + 1))))
            Invariant((self.get_hof_idx() - self.get_iof_idx()) < self.get_iof_hops(iof))
            Invariant(Let(cast(InfoOpaqueField, self.ofs_get_by_idx(self.get_iof_idx())), bool, lambda iof:
                        Implies((Let(cast(HopOpaqueField, self.ofs_get_by_idx(self.get_hof_idx() + 1)), bool, lambda hof:
                                    not self.get_hof_xover(hof) or
                                    self.get_iof_shortcut(iof)
                                    ) and
                                    (self.get_hof_idx() != self.get_iof_idx() + self.get_iof_hops(iof))),
                                self.get_hof_idx() + 2 < self.get_ofs_len() and
                                isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 2), HopOpaqueField) and
                                self.ofs_get_by_idx(self.get_hof_idx() + 2) is not self.ofs_get_by_idx(self.get_hof_idx() + 1)
                                )
                    )
                )
            Invariant(Implies(self.get_hof_idx() < self.get_ofs_len() - 2, isinstance(self.ofs_get_by_idx(self.get_hof_idx() + 2), HopOpaqueField)))
            Invariant(self.get_ofs_contents() is Old(self.get_ofs_contents()))
            Invariant(skipped_verify_only is False)
            Invariant(MustTerminate(1))
            Unfold(self.State())
            self._hof_idx += 1
            Fold(Acc(self.State()))
            if (self.get_hof_idx() - self.get_iof_idx()) > self.get_iof_hops(iof):
                # Switch to the next segment
                Unfold(self.State())
                self._iof_idx = self._hof_idx
                Fold(Acc(self.State()))
                iof = self.get_iof()
                # Continue looking for a routing HOF
                continue
            hof = self.get_hof()
            if not self.get_hof_verify_only(hof):
                break
            skipped_verify_only = True
        return skipped_verify_only

    @Pure
    def get_of_idxs(self) -> Tuple[int, int]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        """
        Get current InfoOpaqueField and HopOpaqueField indexes.

        :return: Tuple (int, int) of IOF index and HOF index, respectively.
        """
        return self.get_iof_idx(), self.get_hof_idx()

    @Pure
    def __len__(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), len(self._ofs))) * OpaqueField.LEN

    @Pure
    def get_curr_if(self, ingress: bool=True) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        # Requires(MustTerminate(2))
        # Ensures(Acc(self.State(), 1/10))
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        """
        Return the current interface, depending on the direction of the
        segment.
        """
        hof = self.get_hof()
        iof = self.get_iof()
        if ingress == self.get_iof_up_flag(iof):
            return self.get_hof_egress_if(hof)
        return self.get_hof_ingress_if(hof)

    @classmethod
    def from_values(cls, a_iof: InfoOpaqueField=None, a_hofs: List[HopOpaqueField]=None,
                    b_iof: InfoOpaqueField=None, b_hofs: List[HopOpaqueField]=None,
                    c_iof: InfoOpaqueField=None, c_hofs: List[HopOpaqueField]=None) -> 'SCIONPath':
        ...

    """
    Start of helper functions for performance
    """

    @Pure
    def get_iof_idx(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/20))
        Ensures(Implies(Result() is not None, Result() >= 0 and Result() < self.get_ofs_len()))
        return Unfolding(Acc(self.State(), 1/20), self._iof_idx)

    @Pure
    def get_hof_idx(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/20))
        Ensures(Implies(Result() is not None, Result() >= 0 and Result() < self.get_ofs_len()))
        return Unfolding(Acc(self.State(), 1/20), self._hof_idx)

    @Pure
    def get_ofs_contents(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.State(), 1/20))
        return Unfolding(Acc(self.State(), 1/20), self.get_ofs_contents_1())

    @Pure
    def get_ofs_contents_1(self) -> Sequence[OpaqueField]:
        Requires(Acc(self._ofs, 1/20))
        Requires(Acc(self._ofs.State(), 1/20))
        return Unfolding(Acc(self._ofs.State(), 1/20), self._ofs.contents())

    @Pure
    def state_get_ofs_len(self) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        return cast(int, Unfolding(Acc(self._ofs.State(), 1/10), len(self._ofs)))

    @Pure
    def get_ofs_len(self) -> int:
        Requires(Acc(self.State(), 1/20))
        return cast(int, Unfolding(Acc(self.State(), 1/20), self.get_ofs_len_1()))

    @Pure
    def get_ofs_len_1(self) -> int:
        Requires(Acc(self._ofs, 1/20))
        Requires(Acc(self._ofs.State(), 1/20))
        return Unfolding(Acc(self._ofs.State(), 1/20), len(self._ofs))

    @Pure
    def get_ofs(self) -> OpaqueFieldList:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self._ofs)

    @Pure
    def get_ofs_count(self, hofs: str) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self._ofs.count(hofs))

    @Pure
    def get_ofs_label_by_idx(self) -> str:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_hof_idx() is not None)
        return Unfolding(Acc(self.State(), 1/10), self._ofs.get_label_by_idx(self._hof_idx))

    @Pure
    def get_iof_up_flag(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(iof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_iof_up_flag_1(iof))

    @Pure
    def get_iof_up_flag_1(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(iof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), iof.get_up_flag())

    @Pure
    def get_iof_peer(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(iof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_iof_peer_1(iof))

    @Pure
    def get_iof_peer_1(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(iof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), iof.get_peer())

    @Pure
    def get_iof_shortcut(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(iof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_iof_shortcut_1(iof))

    @Pure
    def get_iof_shortcut_1(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(iof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), iof.get_shortcut())

    @Pure
    def get_iof_hops(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self.State(), 1/20))
        Requires(iof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/20), self.get_iof_hops_1(iof))

    @Pure
    def get_iof_hops_1(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self._ofs, 1/20))
        Requires(Acc(self._ofs.State(), 1/20))
        Requires(iof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/20), iof.get_hops())

    @Pure
    def get_hof_ingress_if(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(hof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_hof_ingress_if_1(hof))

    @Pure
    def get_hof_ingress_if_1(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(hof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), hof.get_ingress_if())

    @Pure
    def get_hof_egress_if(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(hof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_hof_egress_if_1(hof))

    @Pure
    def get_hof_egress_if_1(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(hof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), hof.get_egress_if())

    @Pure
    def get_hof_exp_time(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(hof in self.get_ofs_contents())
        Ensures(hof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_hof_exp_time_1(hof))

    @Pure
    def get_hof_exp_time_1(self, hof: HopOpaqueField) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(hof in self._ofs.get_contents())
        Ensures((hof in self._ofs.get_contents()))
        return Unfolding(Acc(self._ofs.State(), 1/10), hof.get_exp_time())

    @Pure
    def get_hof_xover(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(hof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_hof_xover_1(hof))

    @Pure
    def get_hof_xover_1(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(hof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), hof.get_xover())

    @Pure
    def get_hof_verify_only(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(hof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_hof_verify_only_1(hof))

    @Pure
    def get_hof_verify_only_1(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(hof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), hof.get_verify_only())

    @Pure
    def get_iof_timestamp(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(iof in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_iof_timestamp_1(iof))

    @Pure
    def get_iof_timestamp_1(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        Requires(iof in self._ofs.get_contents())
        return Unfolding(Acc(self._ofs.State(), 1/10), iof.get_timestamp())

    @Pure
    def ofs_get_by_idx(self, idx: int) -> OpaqueField:
        Requires(Acc(self.State(), 1/10))
        Requires(idx >= 0 and idx < self.get_ofs_len())
        Ensures(Result() in self.get_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(idx))

    """
    Helper functions for non-pure functions
    """
    @Pure
    @ContractOnly
    def get_hof_ver_pure(self) -> Optional[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_iof_idx() is not None)
        Requires(self.get_hof_idx() is not None)
        Ensures(self.get_iof_idx() is not None)
        Ensures(self.get_hof_idx() is not None)
        Ensures(Implies(Result() is not None, Result() in self.get_ofs_contents()))
        Ensures(Implies(Result() is not None, Result() is not self.get_hof()))
        ...


@Pure
def valid_hof(path: SCIONPath, ingress: bool, interface_if_id: int, of_gen_key: bytes) -> bool:
    Requires(Acc(path.State(), 1/10))
    Requires(path.get_iof_idx() is not None)
    Requires(path.get_hof_idx() is not None)
    return (not (path.get_curr_if(ingress=ingress) != interface_if_id) and
            Let(path.get_hof(), bool, lambda hof:
            Let(path.get_iof(), bool, lambda iof:
            Let(path.get_iof_timestamp(iof), bool, lambda ts:
            Let(path.get_hof_ver_pure(), bool, lambda prev_hof:
            int(SCIONTime.get_time()) <= ts + path.get_hof_exp_time(hof) * EXP_TIME_UNIT and
            Unfolding(Acc(path.State(), 1/10), Unfolding(Acc(path._ofs.State(), 1/10), hof.verify_mac(of_gen_key, ts, prev_hof))))))))

@Pure
# @ContractOnly
def incremented(path: SCIONPath) -> bool:
    Requires(Acc(path.State(), 1/10))
    # Ensures(Result().get_hof_idx() == path.get_hof_idx() + 1)
    return True # for now try this
