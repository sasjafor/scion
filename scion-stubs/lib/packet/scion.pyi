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
from nagini_contracts.contracts import *
from nagini_contracts.io_builtins import MustTerminate


@Pure
@ContractOnly
def is_wellformed_packet(packet: bytes) -> bool:
    pass

@Pure
def is_valid_packet(packet: 'SCIONL4Packet') -> bool:
    Requires(Acc(packet.State(), 1/1000))
    return True


@Pure
@ContractOnly
def get_version(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_source_addr_type(raw: bytes) -> int:
    pass

@Pure
@ContractOnly
def get_dest_addr_type(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_addrs_len(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_total_len(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_iof_idx(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_hof_idx(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_next_hdr(raw: bytes) -> int:
    pass


@Pure
@ContractOnly
def get_hdr_len(raw: bytes) -> int:
    pass


class SCIONCommonHdr(Serializable):
    NAME = "SCIONCommonHdr"
    LEN = 8

    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        Ensures(self.State())
        self.version = 0  # Version of SCION packet.
        self.src_addr_type = None  # type: Optional[int]
        self.dst_addr_type = None  # type: Optional[int]
        self.addrs_len = None  # type: Optional[int]
        self.total_len = None  # type: Optional[int]
        self._iof_idx = None  # type: Optional[int]
        self._hof_idx = None  # type: Optional[int]
        self.next_hdr = None  # type: Optional[int]
        self.hdr_len = None  # type: Optional[int]
        Fold(self.State())

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

    @Pure
    def matches(self, raw: bytes) -> bool:
        Requires(self.State())
        return Unfolding(self.State(), self.version is get_version(raw) and
                self.src_addr_type is get_source_addr_type(raw) and
                self.dst_addr_type is get_dest_addr_type(raw) and
                self.total_len is get_total_len(raw) and
                self.hdr_len is get_hdr_len(raw) and
                self._iof_idx is get_iof_idx(raw) and
                self._hof_idx is get_hof_idx(raw) and
                self.next_hdr is get_next_hdr(raw))

    @Predicate
    def State(self) -> bool:
        return (Acc(self.version) and
                Acc(self.src_addr_type) and
                Acc(self.dst_addr_type) and
                Acc(self.addrs_len) and
                Acc(self.total_len) and
                Acc(self._iof_idx) and
                Acc(self._hof_idx) and
                Acc(self.next_hdr) and
                Acc(self.hdr_len))


class SCIONAddrHdr(Serializable):

    BLK_SIZE = 8

    def __init__(self) -> None:  # pragma: no cover
        Ensures(self.State())
        self.src = None  # type: Optional[SCIONAddr]
        self.dst = None  # type: Optional[SCIONAddr]
        self._pad_len = None  # type: Optional[int]
        self._total_len = None  # type: Optional[int]
        Fold(self.State())

    @Pure
    def matches(self, raw: bytes) -> bool:
        Requires(self.State())
        return Unfolding(self.State(), self.src.matches(raw, SCIONCommonHdr.LEN) and
                self.dst.matches(raw, SCIONCommonHdr.LEN + addr_len(self.src)) and
                self._total_len == self.total_len())

    @Pure
    def total_len(self) -> int:
        Requires(self.State())
        data_len = Unfolding(self.State(), addr_len(self.src) + addr_len(self.dst))
        return calc_padding(data_len, SCIONAddrHdr.BLK_SIZE)

    @Predicate
    def State(self) -> bool:
        return (Acc(self.src) and
                Implies(self.src is not None, self.src.State()) and
                Acc(self.dst) and
                Implies(self.dst is not None, self.dst.State()) and
                Acc(self._pad_len) and
                Acc(self._total_len))

@Pure
def addr_len(addr: SCIONAddr) -> int:
    Requires(Acc(addr.State()))
    Requires(Unfolding(addr.State(), addr.host.TYPE is AddrType.IPV4 or addr.host.TYPE is AddrType.IPV6 or addr.host.TYPE is AddrType.SVC))
    type_ = Unfolding(addr.State(), addr.host.TYPE)
    if type_ == AddrType.IPV4:
        return ISD_AS.LEN + HostAddrIPv4.LEN
    if type_ == AddrType.IPV6:
        return ISD_AS.LEN + HostAddrIPv6.LEN
    return ISD_AS.LEN + HostAddrSVC.LEN


class SCIONBasePacket(PacketBase, Sized):
    NAME = "SCIONBasePacket"

    def __init__(self, raw:bytes=None) -> None:  # pragma: no cover
        self.cmn_hdr = None  # type: Optional[SCIONCommonHdr]
        self.addrs = None  # type: Optional[SCIONAddrHdr]
        self.path = None  # type: Optional[SCIONPath]
        self._l4_proto = 0
        self._payload = b""

    def pack(self) -> bytes:
        Requires(Acc(self.State(), 1/100))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/100) and Result() is packed(self))
        ...

    def reversed_copy(self) -> 'SCIONBasePacket':
        ...

    @Predicate
    def State(self) -> bool:
        return (Acc(self.cmn_hdr) and
                Implies(self.cmn_hdr is not None, self.cmn_hdr.State()) and
                Acc(self.addrs) and
                Implies(self.addrs is not None, self.addrs.State()) and
                Acc(self.path) and
                Implies(self.path is not None, self.path.State()))


class SCIONExtPacket(SCIONBasePacket):
    def __init__(self, raw: bytes=None) -> None:  # pragma: no cover
        self.ext_hdrs = []  # type: List[Union[SCMPExt, SibraExtBase]]
        super().__init__(raw)

    @Predicate
    def State(self) -> bool:
        return (Acc(self.ext_hdrs) and Acc(list_pred(self.ext_hdrs)) and
                Forall(self.ext_hdrs, lambda e: (e.State(), [])))


class SCIONL4Packet(SCIONExtPacket):
    NAME = "SCIONL4Packet"

    def __init__(self, raw: bytes=None) -> None:  # pragma: no cover
        Ensures(raw is not None and is_wellformed_packet(raw))
        Ensures(self.State())
        Ensures(self.matches(raw))
        Exsures(SCMPError, raw is None or not is_wellformed_packet(raw))
        Exsures(SCIONBaseError, raw is None or not is_wellformed_packet(raw))
        self.l4_hdr = None  # type: Optional[L4HeaderBase]

    @Pure
    def matches(self, packet: bytes) -> bool:
        Requires(self.State())
        Requires(is_wellformed_packet(packet))
        return Unfolding(self.State(), self.cmn_hdr.matches(packet) and
                self.addrs.matches(packet) and
                self.path.matches(packet, Unfolding(self.addrs.State(), self.addrs._total_len)) and
                extensions_match(Unfolding(self.cmn_hdr.State(), self.cmn_hdr.next_hdr), self.ext_hdrs, packet, Unfolding(self.cmn_hdr.State(), self.cmn_hdr.hdr_len)) and
                self.l4_hdr.matches(packet, Unfolding(self.cmn_hdr.State(), self.cmn_hdr.hdr_len) + extension_len(self.ext_hdrs)))

    @Predicate
    def State(self) -> bool:
        return (Acc(self.l4_hdr) and
                Implies(self.l4_hdr is not None, self.l4_hdr.State()))

    def update(self) -> None:
        ...

    def parse_payload(self) -> SCMPPayload:
        ...

    @Pure
    def __len__(self) -> int:
        ...

    def validate(self, pkt_len: int) -> None:
        Requires(Acc(self.State(), 1/2))
        Ensures(Acc(self.State(), 1/2))
        Ensures(is_valid_packet(self))
        Exsures(SCMPError, Acc(self.State(), 1/2) and not is_valid_packet(self))
        Exsures(SCIONChecksumFailed, Acc(self.State(), 1/2) and not is_valid_packet(self))
        ...

@Pure
@ContractOnly
def packed(spkt: SCIONBasePacket) -> bytes:
    Requires(Acc(spkt.State(), 1/1000))

@Pure
def extensions_match(next_hdr: int, hdrs: List[Union[SCMPExt, SibraExtBase]], packet: bytes, offset: int) -> bool:
    Requires(Acc(list_pred(hdrs), 1/200))
    Requires(Forall(hdrs, lambda e: (Acc(e.State(), 1/200), [])))
    if len(hdrs) == 0:
        return next_hdr not in L4Proto.L4
    return False

@Pure
def extension_len(hdrs: List[Union[SCMPExt, SibraExtBase]]) -> int:
    Requires(Acc(list_pred(hdrs), 1/200))
    Requires(Forall(hdrs, lambda e: (Acc(e.State(), 1/200), [])))
    return extension_len_rec(hdrs, 0)

@Pure
def extension_len_rec(hdrs: List[Union[SCMPExt, SibraExtBase]], index: int) -> int:
    Requires(Acc(list_pred(hdrs), 1/200))
    Requires(Forall(hdrs, lambda e: (Acc(e.State(), 1/200), [])))
    Requires(index >= 0 and index <= len(hdrs))
    if index == len(hdrs):
        return 0
    current = hdrs[index]  # type: ExtensionHeader
    return Unfolding(current.State(), current._hdr_len) + extension_len_rec(hdrs, index + 1)

def build_base_hdrs(src: SCIONAddr, dst: SCIONAddr, l4: int =L4Proto.UDP) -> Tuple[SCIONCommonHdr, SCIONAddrHdr]:
    ...
