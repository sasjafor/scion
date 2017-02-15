from lib.packet.packet_base import PacketBase
from lib.util import Raw
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.packet_base import Serializable
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scmp.payload import SCMPPayload
from typing import Optional, Sized


class SCIONCommonHdr(Serializable):
    pass


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


class SCIONExtPacket(SCIONBasePacket):
    def __init__(self, raw: Raw=None) -> None:  # pragma: no cover
        self.ext_hdrs = []  # type: List[ExtensionHeader]
        super().__init__(raw)


class SCIONL4Packet(SCIONExtPacket):
    def update(self) -> None:
        ...

    def parse_payload(self) -> SCMPPayload:
        ...