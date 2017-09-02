from lib.errors import SCIONBaseError, SCIONChecksumFailed
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.packet_base import PacketBase
from lib.util import calc_padding, Raw
from lib.packet.host_addr import HostAddrIPv4, HostAddrIPv6, HostAddrSVC
from lib.packet.packet_base import Serializable, L4HeaderBase
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.errors import SCMPError
from lib.packet.scmp.ext import SCMPExt
from lib.sibra.ext.ext import SibraExtBase
from lib.types import AddrType, L4Proto

from typing import List, Optional, Sized, Tuple, Union




def is_wellformed_packet(packet: bytes) -> bool:
    ...

def is_valid_packet(packet: 'SCIONL4Packet') -> bool:
    return True


def get_version(raw: bytes) -> int:
    ...



def get_source_addr_type(raw: bytes) -> int:
    ...


def get_dest_addr_type(raw: bytes) -> int:
    ...



def get_addrs_len(raw: bytes) -> int:
    ...



def get_total_len(raw: bytes) -> int:
    ...


def get_iof_idx(raw: bytes) -> int:
    ...


def get_hof_idx(raw: bytes) -> int:
    ...



def get_next_hdr(raw: bytes) -> int:
    ...



def get_hdr_len(raw: bytes) -> int:
    ...


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

    # @Pure
    # def matches(self, raw: bytes) -> bool:
    #     Requires(self.State())
    #     return (self.version == (raw[0] // 16) and
    #             self.src_addr_type == ((raw[0] % 16) * 16 + (raw[1] // 64)) and
    #             self.dst_addr_type == (raw[1] % 64) and
    #             self.total_len == (raw[2] * 256 + raw[3]) and
    #             self.hdr_len == raw[4] and
    #             self._iof_idx == raw[5] and
    #             self._hof_idx == raw[6] and
    #             self.next_hdr == raw[7])






class SCIONAddrHdr(Serializable):

    BLK_SIZE = 8

    def __init__(self) -> None:  # pragma: no cover
        self.src = None  # type: Optional[SCIONAddr]
        self.dst = None  # type: Optional[SCIONAddr]
        self._pad_len = None  # type: Optional[int]
        self._total_len = None  # type: Optional[int]



    def total_len(self) -> int:
        data_len = addr_len(self.src) + addr_len(self.dst)
        return calc_padding(data_len, SCIONAddrHdr.BLK_SIZE)



def addr_len(addr: SCIONAddr) -> int:
    type_ = addr.host.TYPE
    if type_ == AddrType.IPV4:
        return ISD_AS.LEN + HostAddrIPv4.LEN
    if type_ == AddrType.IPV6:
        return ISD_AS.LEN + HostAddrIPv6.LEN
    return ISD_AS.LEN + HostAddrSVC.LEN


class SCIONBasePacket(PacketBase):
    NAME = "SCIONBasePacket"

    def __init__(self, raw:bytes=None) -> None:  # pragma: no cover
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
    def __init__(self, raw: bytes=None) -> None:  # pragma: no cover
        self.ext_hdrs = []  # type: List[Union[SCMPExt, SibraExtBase]]
        super().__init__(raw)



class SCIONL4Packet(SCIONExtPacket):
    NAME = "SCIONL4Packet"

    def __init__(self, raw: bytes=None) -> None:  # pragma: no cover
        self.l4_hdr = None  # type: Optional[L4HeaderBase]


    def update(self) -> None:
        ...

    def parse_payload(self) -> SCMPPayload:
        ...

    def __len__(self) -> int:
        ...

    def validate(self, pkt_len: int) -> None:
        ...


def packed(spkt: SCIONBasePacket) -> bytes:
    ...


def build_base_hdrs(src: SCIONAddr, dst: SCIONAddr, l4: int =L4Proto.UDP) -> Tuple[SCIONCommonHdr, SCIONAddrHdr]:
    ...
