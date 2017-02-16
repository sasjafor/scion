from lib.packet.packet_base import PacketBase
from lib.util import Raw
from lib.packet.packet_base import Serializable, L4HeaderBase
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.ext import SCMPExt
from lib.sibra.ext.ext import SibraExtBase

from lib.types import L4Proto

from typing import Optional, Sized, Tuple, Union


class SCIONCommonHdr(Serializable):
    NAME = "SCIONCommonHdr"
    LEN = 8

    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        self.version = 0  # Version of SCION packet.
        self.src_addr_type = None  # type: Optional[int]
        self.dst_addr_type = None  # type: Optional[int]
        self.addrs_len = None  # type: Optional[int]
        self.total_len = None  # type: Optional[int]
        self._iof_idx = None  # type: Optional[int]
        self._hof_idx = None  # type: Optional[int]
        self.next_hdr = None  # type: Optional[int]
        self.hdr_len = None  # type: Optional[int]


class SCIONAddrHdr(Serializable):
    def __init__(self) -> None:  # pragma: no cover
        self.src = None  # type: Optional[SCIONAddr]
        self.dst = None  # type: Optional[SCIONAddr]
        self._pad_len = None  # type: Optional[int]
        self._total_len = None  # type: Optional[int]


class SCIONBasePacket(PacketBase, Sized):
    NAME = "SCIONBasePacket"

    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        self.cmn_hdr = None  # type: Optional[SCIONCommonHdr]
        self.addrs = None  # type: Optional[SCIONAddrHdr]
        self.path = None  # type: Optional[SCIONPath]
        self._l4_proto = 0
        self._payload = b""

    def pack(self) -> bytes:
        ...

    def reversed_copy(self) -> 'SCIONBasePacket':
        ...


class SCIONExtPacket(SCIONBasePacket):
    def __init__(self, raw: Raw=None) -> None:  # pragma: no cover
        self.ext_hdrs = []  # type: List[Union[SCMPExt, SibraExtBase]]
        super().__init__(raw)


class SCIONL4Packet(SCIONExtPacket):
    NAME = "SCIONL4Packet"

    def __init__(self, raw=None):  # pragma: no cover
        self.l4_hdr = None  # type: Optional[L4HeaderBase]

    def update(self) -> None:
        ...

    def parse_payload(self) -> SCMPPayload:
        ...

    def __len__(self) -> int:
        ...

    def validate(self, pkt_len: int) -> None:
        ...


def build_base_hdrs(src: SCIONAddr, dst: SCIONAddr, l4: int =L4Proto.UDP) -> Tuple[SCIONCommonHdr, SCIONAddrHdr]:
    ...