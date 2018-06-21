from nagini_contracts.obligations import MustTerminate

from lib.packet.packet_base import Serializable
from lib.packet.opaque_field import OpaqueField, InfoOpaqueField, HopOpaqueField, OpaqueFieldList
from lib.packet.pcb import ASMarking
from lib.util import Raw
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
        return (Acc(self._ofs) and self._ofs.State() and
                Acc(self._hof_idx) and
                Acc(self._iof_idx) and
                Implies(self._hof_idx is not None,
                    self._hof_idx >= 0 and self._hof_idx < self.get_ofs_len() and
                    isinstance(self._ofs.get_by_idx(self._hof_idx), HopOpaqueField)) and
                Implies(self._iof_idx is not None,
                    self._iof_idx >= 0 and self._iof_idx < self.get_ofs_len() and
                    isinstance(self._ofs.get_by_idx(self._iof_idx), InfoOpaqueField)) and
                Implies(self._hof_idx is not None and
                        self._iof_idx is not None,
                        Let(cast(InfoOpaqueField, self._ofs.get_by_idx(self._iof_idx)), bool, lambda iof:
                        Let(self._hof_idx, bool, lambda hof_idx :
                        Implies(Unfolding(self._ofs.State(), iof.get_up_flag()),
                                hof_idx >= 0 and hof_idx + 1 >= 0 and hof_idx < self.get_ofs_len() - 1 and hof_idx + 1 < self.get_ofs_len() and isinstance(self._ofs.get_by_idx(hof_idx + 1), HopOpaqueField)) and
                        Implies(not Unfolding(self._ofs.State(), iof.get_up_flag()),
                                hof_idx >= 1 and hof_idx < self.get_ofs_len() and isinstance(self._ofs.get_by_idx(hof_idx - 1), HopOpaqueField))
                        ))) and
                Acc(self.interfaces) and Acc(list_pred(self.interfaces)) and
                Acc(self.mtu))

    @Pure
    def get_ofs_len(self) -> int:
        Requires(Acc(self._ofs, 1/10))
        Requires(Acc(self._ofs.State(), 1/10))
        return cast(int, Unfolding(Acc(self._ofs.State(), 1/10), len(self._ofs)))

    @Pure
    def matches(self, raw: bytes, offset: int) -> bool:
        return True

    @Pure
    def get_iof(self) -> Optional[InfoOpaqueField]:  # pragma: no cover
        Requires(Acc(self.State(), 1/10))
        Ensures(Implies(Result() is not None, Result() in Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), self._ofs.contents()))))
        idx = Unfolding(Acc(self.State(), 1/10), self._iof_idx)
        if not idx is not None:
            return None
        return cast(InfoOpaqueField, Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(idx)))

    @Pure
    def get_hof(self) -> Optional[HopOpaqueField]:  # pragma: no cover
        Requires(Acc(self.State(), 1/10))
        Ensures(Implies(Result() is not None, Result() in Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), self._ofs.contents()))))
        idx = Unfolding(Acc(self.State(), 1/10), self._hof_idx)
        if not idx is not None:
            return None
        return cast(HopOpaqueField, Unfolding(Acc(self.State(), 1/10), self._ofs.get_by_idx(idx)))

    def get_hof_ver(self, ingress: bool =True) -> Optional[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None and self._hof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), Let(cast(InfoOpaqueField, self._ofs.get_by_idx(self._iof_idx)), bool, lambda iof:
                    Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), not iof.peer)))))
        Requires(MustTerminate(3))
        Ensures(Acc(self.State(), 1/10))
        #Ensures(Implies(Result() is not None, Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Result() in self._ofs.contents()))))
        """Return the :any:`HopOpaqueField` needed to verify the current HOF."""
        iof = self.get_iof()
        hof = self.get_hof()
        if Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), not hof.xover or (iof.shortcut and not iof.peer))))):
            # For normal hops on any type of segment, or cross-over hops on
            # non-peer shortcut hops, just use next/prev HOF.
            return self._get_hof_ver_normal(iof)
        iof_peer = Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.peer)))
        iof_up_flag = Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.up_flag)))
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
        Requires(Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), iof in self._ofs.contents())))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), iof is self._ofs.get_by_idx(self._iof_idx)))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        # Requires(Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), Implies((not ((iof.up_flag and self._hof_idx == self._iof_idx + iof.hops) or (
        #         not iof.up_flag and self._hof_idx == self._iof_idx + 1))) and iof.up_flag, self._hof_idx < len(self._ofs) - 1)))))
        # Requires(Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), Implies((not (iof.up_flag and self._hof_idx == self._iof_idx + iof.hops) or (
        #         not iof.up_flag and self._hof_idx == self._iof_idx + 1)) and not iof.up_flag, self._hof_idx > 0)))))
        # Requires iof in bla
        # If this is the last hop of an Up path, or the first hop of a Down
        # path, there's no previous HOF to verify against.
        if Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), (iof.up_flag and self._hof_idx == self._iof_idx + iof.hops) or (
                not iof.up_flag and self._hof_idx == self._iof_idx + 1)))):
            return None
        # Otherwise use the next/prev HOF based on the up flag.
        offset = 1 if Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.up_flag))) else -1
        return Unfolding(Acc(self.State(), 1/10), cast(HopOpaqueField, self._ofs.get_by_idx(self._hof_idx + offset)))

    def is_on_last_segment(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        label = Unfolding(Acc(self.State(), 1/10), self._ofs.get_label_by_idx(self._hof_idx))
        if label == self.A_HOFS:
            return Unfolding(Acc(self.State(), 1/10), self._ofs.count(self.B_HOFS)) == 0
        elif label == self.B_HOFS:
            return Unfolding(Acc(self.State(), 1/10), self._ofs.count(self.C_HOFS)) == 0
        else:
            return True

    def get_fwd_if(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        """Return the interface to forward the current packet to."""
        if not Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), len(self._ofs))):
            return 0
        iof = self.get_iof()
        hof = self.get_hof()
        if Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.up_flag))):
            return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.ingress_if)))
        return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.egress_if)))

    def inc_hof_idx(self) -> bool:
        Requires(Acc(self.State()))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        Ensures(Acc(self.State()))
        Ensures(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Ensures(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        """
        Increment the HOF idx to next routing HOF.

        Skip VERIFY_ONLY HOFs, as they are not used for routing.
        Also detect when there are no HOFs left in the current segment, and
        switch to the next segment, before restarting.
        """
        iof = self.get_iof()
        skipped_verify_only = False
        while True:
            Invariant(Acc(self.State()))
            # Invariant(Acc(self._hof_idx))
            # Invariant(Acc(self._iof_idx))
            # Invariant(Acc(self._ofs))
            # Invariant(Acc(self._ofs.State()))
            Invariant(Unfolding(self.State(), self._hof_idx is not None))
            Invariant(Unfolding(self.State(), self._iof_idx is not None))
            # Invariant(Unfolding(self.State(), isinstance(self._hof_idx, int)))
            # Invariant(Unfolding(self.State(), isinstance(self._iof_idx, int)))
            Invariant(iof in Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), self._ofs.contents())))
            # Invariant(Unfolding(Acc(self.State()), (self._hof_idx >= 0) and (self._hof_idx < Unfolding(Acc(self._ofs.State()), len(self._ofs))) and isinstance(self._ofs.get_by_idx(self._hof_idx), HopOpaqueField)))
            Unfold(self.State())
            self._hof_idx += 1
            # Assert(iof in self._ofs.contents())
            if (self._hof_idx - self._iof_idx) > Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.hops)):
                # Switch to the next segment
                self._iof_idx = self._hof_idx
                Fold(Acc(self.State()))
                iof = self.get_iof()
                # Unfold(Acc(self.State(), 1/10))
                # Continue looking for a routing HOF
                # Fold(self.State())
                continue
            Fold(Acc(self.State(), 1/10))
            hof = self.get_hof()
            Unfold(Acc(self.State(), 1/10))
            if not Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.verify_only)):
                Fold(self.State())
                break
            skipped_verify_only = True
            Fold(self.State())
        return skipped_verify_only

    @Pure
    def get_of_idxs(self) -> Tuple[int, int]:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        """
        Get current InfoOpaqueField and HopOpaqueField indexes.

        :return: Tuple (int, int) of IOF index and HOF index, respectively.
        """
        return Unfolding(Acc(self.State(), 1/10), self._iof_idx), Unfolding(Acc(self.State(), 1/10), self._hof_idx)

    @Pure
    def __len__(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), len(self._ofs))) * OpaqueField.LEN

    def get_curr_if(self, ingress: bool=True) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(Unfolding(Acc(self.State(), 1/10), self._iof_idx is not None))
        Requires(Unfolding(Acc(self.State(), 1/10), self._hof_idx is not None))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10))
        """
        Return the current interface, depending on the direction of the
        segment.
        """
        hof = self.get_hof()
        iof = self.get_iof()
        if ingress == Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(iof.State(), 1/10), iof.up_flag))):
            return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.egress_if)))
        return Unfolding(Acc(self.State(), 1/10), Unfolding(Acc(self._ofs.State(), 1/10), Unfolding(Acc(hof.State(), 1/10), hof.ingress_if)))

    @classmethod
    def from_values(cls, a_iof: InfoOpaqueField=None, a_hofs: List[HopOpaqueField]=None,
                    b_iof: InfoOpaqueField=None, b_hofs: List[HopOpaqueField]=None,
                    c_iof: InfoOpaqueField=None, c_hofs: List[HopOpaqueField]=None) -> 'SCIONPath':
        ...


@Pure
def valid_hof(path: SCIONPath) -> bool:
    Requires(Acc(path.State(), 1/10))
    return True