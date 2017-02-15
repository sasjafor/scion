from lib.packet.packet_base import Serializable
from lib.packet.opaque_field import InfoOpaqueField, HopOpaqueField, OpaqueFieldList
from lib.packet.pcb import ASMarking
from lib.util import Raw
from typing import Optional, Sized, List, Tuple

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
        self._ofs = None  # type: OpaqueFieldList
        self._iof_idx = None  # type: Optional[int]
        self._hof_idx = None  # type: Optional[int]
        self.interfaces = []  # type: List[Tuple[ASMarking, int]]
        self.mtu = None  # type: Optional[int]

    def get_iof(self) -> Optional[InfoOpaqueField]:  # pragma: no cover
        ...

    def get_hof(self) -> Optional[HopOpaqueField]:  # pragma: no cover
        ...

    def get_hof_ver(self, ingress: bool =True) -> Optional[HopOpaqueField]:
        ...

    def is_on_last_segment(self) -> bool:
        ...

    def get_fwd_if(self) -> int:
        ...

    def inc_hof_idx(self) -> None:
        ...