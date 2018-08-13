from lib.errors import SCIONBaseError, SCIONChecksumFailed
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.opaque_field import OpaqueFieldList, HopOpaqueField, OpaqueField, InfoOpaqueField
from lib.packet.packet_base import PacketBase
from lib.util import calc_padding, Raw
from lib.packet.host_addr import HostAddrIPv4, HostAddrIPv6, HostAddrSVC, HostAddrBase  # , HostAddrInvalidType
from lib.packet.packet_base import Serializable, L4HeaderBase
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.scmp.errors import SCMPError, SCMPBadSrcType, SCMPBadDstType
from lib.packet.scmp.ext import SCMPExt
from lib.sibra.ext.ext import SibraExtBase
from lib.types import AddrType, L4Proto

from typing import List, Optional, Sized, Tuple, Union, cast
from nagini_contracts.contracts import *
from nagini_contracts.io_builtins import MustTerminate


@Pure
@ContractOnly
def is_wellformed_packet(packet: bytes) -> bool:
    pass

@Pure
def is_valid_packet(packet: 'SCIONL4Packet') -> bool:
    Requires(packet.State())
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
        Requires(Acc(self.src.State()))
        Requires(AddressType(self.src))
        return Unfolding(self.State(), self.src.matches(raw, SCIONCommonHdr.LEN) and
                self.dst.matches(raw, SCIONCommonHdr.LEN + addr_len(self.src)) and
                self._total_len == self.total_len())

    @Pure
    def total_len(self) -> int:
        Requires(self.State())
        Requires(Acc(self.dst.State()))
        Requires(AddressType(self.dst))
        data_len = Unfolding(self.State(), addr_len(self.src) + addr_len(self.dst))
        return calc_padding(data_len, SCIONAddrHdr.BLK_SIZE)

    def pack(self) -> bytes:
        ...
        # self.update()
        # packed = []
        # packed.append(self.src.pack())
        # packed.append(self.dst.pack())
        # packed.append(bytes(self._pad_len))
        # raw = b"".join(packed)
        # assert len(raw) % self.BLK_SIZE == 0
        # assert len(raw) == self._total_len
        # return raw

    def update(self) -> None:
        ...
        # self._total_len, self._pad_len = self.calc_lens(
        #     self.src.host.TYPE, self.dst.host.TYPE)

    # @classmethod
    # def calc_lens(cls, src_type, dst_type):
    #     try:
    #         data_len = SCIONAddr.calc_len(src_type)
    #     except HostAddrInvalidType:
    #         raise SCMPBadSrcType(
    #             "Unsupported src address type: %s" % src_type) from None
    #     try:
    #         data_len += SCIONAddr.calc_len(dst_type)
    #     except HostAddrInvalidType:
    #         raise SCMPBadDstType(
    #             "Unsupported dst address type: %s" % dst_type) from None
    #     pad_len = calc_padding(data_len, cls.BLK_SIZE)
    #     total_len = data_len + pad_len
    #     assert total_len % cls.BLK_SIZE == 0
    #     return total_len, pad_len

    @Predicate
    def State(self) -> bool:
        return (Acc(self.src) and
                Implies(self.src is not None, self.src.State()) and
                Acc(self.dst) and
                Implies(self.dst is not None, self.dst.State()) and
                Acc(self._pad_len) and
                Acc(self._total_len))

@Predicate
def AddressType(addr: SCIONAddr) -> bool:
    return Acc(addr.State()) and Unfolding(addr.State(), addr.host.TYPE is AddrType.IPV4 or addr.host.TYPE is AddrType.IPV6 or addr.host.TYPE is AddrType.SVC)

@Pure
def addr_len(addr: SCIONAddr) -> int:
    Requires(Acc(addr.State()))
    Requires(AddressType(addr))
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
        Requires(Acc(self.State(), 1/10))
        Requires(MustTerminate(2))
        Ensures(Acc(self.State(), 1/10) and Result() is packed(self))
        ...

    def reversed_copy(self) -> 'SCIONBasePacket':
        ...

    def short_desc(self) -> str:
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
        self.ext_hdrs = []  # type: List[ExtensionHeader]
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

    # @Predicate
    # def PreState(self) -> bool:
    #     """
    #     PreState of packet, meaning the State a packet needs to have before the call to SCIONPath.inc_hof_idx
    #     """
    #     return (Acc(self.State()) and
    #             Unfolding(Acc(self.State()),
    #             Let(self.path, bool, lambda path:
    #                 path.get_hof_idx() < path.get_ofs_len() - 1 and
    #                 Let(cast(HopOpaqueField, Unfolding(Acc(path.State()), path._ofs.get_by_idx(path._hof_idx + 1))), bool, lambda hof:
    #                     not path.get_hof_verify_only(hof)) and
    #                 path.get_hof_idx() - path.get_iof_idx() < path.get_iof_hops(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx()))) and
    #                 Let(cast(InfoOpaqueField, path.ofs_get_by_idx(path.get_iof_idx())), bool, lambda iof:
    #                 Implies((Let(cast(HopOpaqueField, path.ofs_get_by_idx(path.get_hof_idx() + 1)), bool, lambda hof:
    #                     not path.get_hof_xover(hof) or
    #                     path.get_iof_shortcut(iof)
    #                  ) and
    #                 (path.get_hof_idx() != path.get_iof_idx() + path.get_iof_hops(iof))),
    #                     path.get_hof_idx() + 2 < path.get_ofs_len() and
    #                     isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField) and
    #                     path.ofs_get_by_idx(path.get_hof_idx() + 2) is not path.ofs_get_by_idx(path.get_hof_idx() + 1)
    #                 )
    #                 ) and
    #                 Implies(path.get_hof_idx() < path.get_ofs_len() - 2,
    #                     isinstance(path.ofs_get_by_idx(path.get_hof_idx() + 2), HopOpaqueField))
    #                 )
    #             ))


    def update(self) -> None:
        Requires(MustTerminate(1))
        Requires(Acc(self.State(), 1/20))
        Ensures(Acc(self.State(), 1/20))
        ...

    def parse_payload(self) -> SCMPPayload:
        Requires(MustTerminate(7))
        pass

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

    def convert_to_scmp_error(self, addr: SCIONAddr, class_: object, type_: object, pkt: SCIONL4Packet, *args: object, hopbyhop: bool=False, **kwargs: object) -> None:
        ...

    """
    Start of performance helper functions
    """

    @Pure
    def get_addrs_dst_isd_as(self) -> Optional[ISD_AS]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_dst() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_dst_isd_as_1())

    @Pure
    def get_addrs_dst_isd_as_1(self) -> Optional[ISD_AS]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_dst_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_dst_isd_as_2())

    @Pure
    def get_addrs_dst_isd_as_2(self) -> Optional[ISD_AS]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.State(), 1/10))
        return Unfolding(Acc(self.addrs.dst.State(), 1/10), self.addrs.dst.isd_as)

    @Pure
    def get_addrs_src_isd_as(self) -> Optional[ISD_AS]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_src() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_src_isd_as_1())

    @Pure
    def get_addrs_src_isd_as_1(self) -> Optional[ISD_AS]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_src_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_src_isd_as_2())

    @Pure
    def get_addrs_src_isd_as_2(self) -> Optional[ISD_AS]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.State(), 1/10))
        return Unfolding(Acc(self.addrs.src.State(), 1/10), self.addrs.src.isd_as)

    @Pure
    def get_addrs_dst_isd_as_isd(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_dst() is not None)
        Requires(self.get_addrs_dst_isd_as() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_dst_isd_as_isd_1())

    @Pure
    def get_addrs_dst_isd_as_isd_1(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_dst_1() is not None)
        Requires(self.get_addrs_dst_isd_as_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_dst_isd_as_isd_2())

    @Pure
    def get_addrs_dst_isd_as_isd_2(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.State(), 1/10))
        Requires(self.get_addrs_dst_isd_as_2() is not None)
        return Unfolding(Acc(self.addrs.dst.State(), 1/10), self.get_addrs_dst_isd_as_isd_3())

    @Pure
    def get_addrs_dst_isd_as_isd_3(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.isd_as, 1/10))
        Requires(Acc(self.addrs.dst.isd_as.State(), 1/10))
        return Unfolding(Acc(self.addrs.dst.isd_as.State(), 1/10), self.addrs.dst.isd_as._isd)
    
    @Pure
    def get_addrs_dst_isd_as_as(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_dst() is not None)
        Requires(self.get_addrs_dst_isd_as() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_dst_isd_as_as_1())

    @Pure
    def get_addrs_dst_isd_as_as_1(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_dst_1() is not None)
        Requires(self.get_addrs_dst_isd_as_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_dst_isd_as_as_2())

    @Pure
    def get_addrs_dst_isd_as_as_2(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.State(), 1/10))
        Requires(self.get_addrs_dst_isd_as_2() is not None)
        return Unfolding(Acc(self.addrs.dst.State(), 1/10), self.get_addrs_dst_isd_as_as_3())

    @Pure
    def get_addrs_dst_isd_as_as_3(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.isd_as, 1/10))
        Requires(Acc(self.addrs.dst.isd_as.State(), 1/10))
        return Unfolding(Acc(self.addrs.dst.isd_as.State(), 1/10), self.addrs.dst.isd_as._as)

    @Pure
    def get_addrs_src_isd_as_isd(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_src() is not None)
        Requires(self.get_addrs_src_isd_as() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_src_isd_as_isd_1())

    @Pure
    def get_addrs_src_isd_as_isd_1(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_src_1() is not None)
        Requires(self.get_addrs_src_isd_as_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_src_isd_as_isd_2())

    @Pure
    def get_addrs_src_isd_as_isd_2(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.State(), 1/10))
        Requires(self.get_addrs_src_isd_as_2() is not None)
        return Unfolding(Acc(self.addrs.src.State(), 1/10), self.get_addrs_src_isd_as_isd_3())

    @Pure
    def get_addrs_src_isd_as_isd_3(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.isd_as, 1/10))
        Requires(Acc(self.addrs.src.isd_as.State(), 1/10))
        return Unfolding(Acc(self.addrs.src.isd_as.State(), 1/10), self.addrs.src.isd_as._isd)
    
    @Pure
    def get_addrs_src_isd_as_as(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_src() is not None)
        Requires(self.get_addrs_src_isd_as() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_src_isd_as_as_1())

    @Pure
    def get_addrs_src_isd_as_as_1(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_src_1() is not None)
        Requires(self.get_addrs_src_isd_as_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_src_isd_as_as_2())

    @Pure
    def get_addrs_src_isd_as_as_2(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.State(), 1/10))
        Requires(self.get_addrs_src_isd_as_2() is not None)
        return Unfolding(Acc(self.addrs.src.State(), 1/10), self.get_addrs_src_isd_as_as_3())

    @Pure
    def get_addrs_src_isd_as_as_3(self) -> int:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.isd_as, 1/10))
        Requires(Acc(self.addrs.src.isd_as.State(), 1/10))
        return Unfolding(Acc(self.addrs.src.isd_as.State(), 1/10), self.addrs.src.isd_as._as)

    @Pure
    def get_addrs(self) -> Optional[SCIONAddrHdr]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.addrs)

    @Pure
    def get_cmn_hdr(self) -> Optional[SCIONCommonHdr]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.cmn_hdr)

    @Pure
    def get_path(self) -> Optional[SCIONPath]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.path)

    @Pure
    def get_addrs_total_len(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_total_len_1())

    @Pure
    def get_addrs_total_len_1(self) -> Optional[int]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        return Unfolding(Acc(self.addrs.State(), 1/10), self.addrs._total_len)

    @Pure
    def get_addrs_dst(self) -> Optional[SCIONAddr]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_dst_1())

    @Pure
    def get_addrs_dst_1(self) -> Optional[SCIONAddr]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        return Unfolding(Acc(self.addrs.State(), 1/10), self.addrs.dst)

    @Pure
    def get_addrs_dst_host(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_dst() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_dst_host_1())

    @Pure
    def get_addrs_dst_host_1(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_dst_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_dst_host_2())

    @Pure
    def get_addrs_dst_host_2(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.State(), 1/10))
        return Unfolding(Acc(self.addrs.dst.State(), 1/10), self.addrs.dst.host)

    @Pure
    def get_addrs_dst_host_addr(self) -> Optional[bytes]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_dst() is not None)
        Requires(self.get_addrs_dst_host() is not None)
        return Unfolding(Acc(self.State(), 1 / 10), self.get_addrs_dst_host_addr_1())

    @Pure
    def get_addrs_dst_host_addr_1(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_dst_1() is not None)
        Requires(self.get_addrs_dst_host_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_dst_host_addr_2())

    @Pure
    def get_addrs_dst_host_addr_2(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.State(), 1/10))
        Requires(self.get_addrs_dst_host_2() is not None)
        return Unfolding(Acc(self.addrs.dst.State(), 1/10), self.get_addrs_dst_host_addr_3())

    @Pure
    def get_addrs_dst_host_addr_3(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.dst, 1/10))
        Requires(Acc(self.addrs.dst.host, 1/10))
        Requires(Acc(self.addrs.dst.host.State(), 1/10))
        return Unfolding(Acc(self.addrs.dst.host.State(), 1/10), self.addrs.dst.host.addr)

    @Pure
    def get_addrs_src(self) -> Optional[SCIONAddr]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_src_1())

    @Pure
    def get_addrs_src_1(self) -> Optional[SCIONAddr]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        return Unfolding(Acc(self.addrs.State(), 1/10), self.addrs.src)
    
    @Pure
    def get_addrs_src_host(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_src() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_addrs_src_host_1())

    @Pure
    def get_addrs_src_host_1(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_src_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_src_host_2())

    @Pure
    def get_addrs_src_host_2(self) -> Optional[HostAddrBase]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.State(), 1/10))
        return Unfolding(Acc(self.addrs.src.State(), 1/10), self.addrs.src.host)

    @Pure
    def get_addrs_src_host_addr(self) -> Optional[bytes]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_addrs() is not None)
        Requires(self.get_addrs_src() is not None)
        Requires(self.get_addrs_src_host() is not None)
        return Unfolding(Acc(self.State(), 1 / 10), self.get_addrs_src_host_addr_1())

    @Pure
    def get_addrs_src_host_addr_1(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.State(), 1/10))
        Requires(self.get_addrs_src_1() is not None)
        Requires(self.get_addrs_src_host_1() is not None)
        return Unfolding(Acc(self.addrs.State(), 1/10), self.get_addrs_src_host_addr_2())

    @Pure
    def get_addrs_src_host_addr_2(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.State(), 1/10))
        Requires(self.get_addrs_src_host_2() is not None)
        return Unfolding(Acc(self.addrs.src.State(), 1/10), self.get_addrs_src_host_addr_3())

    @Pure
    def get_addrs_src_host_addr_3(self) -> Optional[bytes]:
        Requires(Acc(self.addrs, 1/10))
        Requires(Acc(self.addrs.src, 1/10))
        Requires(Acc(self.addrs.src.host, 1/10))
        Requires(Acc(self.addrs.src.host.State(), 1/10))
        return Unfolding(Acc(self.addrs.src.host.State(), 1/10), self.addrs.src.host.addr)

    @Pure
    def get_path_hof_idx(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_path_hof_idx_1())

    @Pure
    def get_path_hof_idx_1(self) -> Optional[int]:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        return Unfolding(Acc(self.path.State(), 1 / 10), self.path._hof_idx)

    @Pure
    def get_path_iof_idx(self) -> Optional[int]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_path_iof_idx_1())

    @Pure
    def get_path_iof_idx_1(self) -> Optional[int]:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        return Unfolding(Acc(self.path.State(), 1 / 10), self.path._iof_idx)

    @Pure
    def get_path_ofs(self) -> OpaqueFieldList:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.get_path_ofs_1())

    @Pure
    def get_path_ofs_1(self) -> OpaqueFieldList:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        return Unfolding(Acc(self.path.State(), 1/10), self.path._ofs)

    @Pure
    def get_ext_hdrs_len(self) -> int:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/100), len(self.ext_hdrs))

    @Pure
    def get_ext_hdrs(self) -> List[ExtensionHeader]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/100), self.ext_hdrs)

    @Pure
    def get_path_len(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), len(self.path))

    @Pure
    def get_path_hof(self) -> Optional[HopOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Ensures(Implies(self.get_path_hof_idx() is not None, Result() is not None))
        Ensures(Implies(Result() is not None, Result() in self.get_path_ofs_contents()))
        return Unfolding(Acc(self.State(), 1/10), self.path.get_hof())

    @Pure
    def get_path_ofs_contents_direct(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.path.get_ofs_contents())

    @Pure
    def get_path_hof_forward_only(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(hof in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_path_hof_forward_only_1(hof))

    @Pure
    def get_path_hof_forward_only_1(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_1())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_hof_forward_only_2(hof))

    @Pure
    def get_path_hof_forward_only_2(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_2())
        return Unfolding(Acc(self.path._ofs.State(), 1/10), hof.get_forward_only())

    @Pure
    def get_path_hof_verify_only(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(hof in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_path_hof_verify_only_1(hof))

    @Pure
    def get_path_hof_verify_only_1(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_1())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_hof_verify_only_2(hof))

    @Pure
    def get_path_hof_verify_only_2(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_2())
        return Unfolding(Acc(self.path._ofs.State(), 1/10), hof.get_verify_only())

    @Pure
    def get_path_hof_xover(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(hof in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_path_hof_xover_1(hof))

    @Pure
    def get_path_hof_xover_1(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_1())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_hof_xover_2(hof))

    @Pure
    def get_path_hof_xover_2(self, hof: HopOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        Requires(hof in self.get_path_ofs_contents_2())
        return Unfolding(Acc(self.path._ofs.State(), 1/10), hof.get_xover())

    @Pure
    def get_path_iof_peer(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(iof in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_path_iof_peer_1(iof))

    @Pure
    def get_path_iof_peer_1(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Requires(iof in self.get_path_ofs_contents_1())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_iof_peer_2(iof))

    @Pure
    def get_path_iof_peer_2(self, iof: InfoOpaqueField) -> bool:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        Requires(iof in self.get_path_ofs_contents_2())
        return Unfolding(Acc(self.path._ofs.State(), 1/10), iof.get_peer())

    @Pure
    def get_path_iof_hops(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(iof in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.get_path_iof_hops_1(iof))

    @Pure
    def get_path_iof_hops_1(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Requires(iof in self.get_path_ofs_contents_1())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_iof_hops_2(iof))

    @Pure
    def get_path_iof_hops_2(self, iof: InfoOpaqueField) -> int:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        Requires(iof in self.get_path_ofs_contents_2())
        return Unfolding(Acc(self.path._ofs.State(), 1/10), iof.get_hops())

    @Pure
    def get_path_ofs_contents(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Ensures(Result() is Unfolding(Acc(self.State(), 1/10), self.path.get_ofs_contents()))
        return Unfolding(Acc(self.State(), 1/10), self.get_path_ofs_contents_1())

    @Pure
    def get_path_ofs_contents_1(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path.State(), 1/10))
        Ensures(self.path is not None)
        Ensures(Result() is self.path.get_ofs_contents())
        return Unfolding(Acc(self.path.State(), 1/10), self.get_path_ofs_contents_2())

    @Pure
    def get_path_ofs_contents_2(self) -> Sequence[OpaqueField]:
        Requires(Acc(self.path, 1/10))
        Requires(Acc(self.path._ofs, 1/10))
        Requires(Acc(self.path._ofs.State(), 1/10))
        return Unfolding(Acc(self.path._ofs.State(), 1/10), self.path._ofs.contents())

    @Pure
    def path_ofs_get_by_idx(self, idx: int) -> OpaqueField:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(idx >= 0 and idx < self.get_path_ofs_len())
        Ensures(self.get_path() is not None)
        Ensures(Result() in self.get_path_ofs_contents())
        return Unfolding(Acc(self.State(), 1/10), self.path.ofs_get_by_idx(idx))

    @Pure
    def get_path_ofs_len(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Ensures(Result() == Unfolding(Acc(self.State(), 1/10), self.path.get_ofs_len()))
        Ensures(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.path.get_ofs_len())

    @Pure
    def path_call_is_on_last_segment(self) -> bool:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(self.get_path_hof_idx() is not None)
        # Ensures(Acc(self.State(), 1/10))
        return Unfolding(Acc(self.State(), 1/10), self.path.is_on_last_segment())

    @Pure
    def get_path_iof(self) -> Optional[InfoOpaqueField]:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.path.get_iof())

    @Pure
    def get_path_fwd_if(self) -> int:
        Requires(Acc(self.State(), 1/10))
        Requires(self.get_path() is not None)
        Requires(self.get_path_iof_idx() is not None)
        Requires(self.get_path_hof_idx() is not None)
        Ensures(self.get_path() is not None)
        Ensures(self.get_path_iof_idx() is not None)
        Ensures(self.get_path_hof_idx() is not None)
        return Unfolding(Acc(self.State(), 1/10), self.path.get_fwd_if())

    # @Pure
    # @ContractOnly
    # def incremented(self) -> None:
    #     Requires(Acc(self.State()))
    #     ...


@Pure
def incremented(spkt: SCIONBasePacket) -> bool:
    Requires(Acc(spkt.State(), 1/10))
    return True

@Pure
@ContractOnly
def packed(spkt: SCIONBasePacket) -> bytes:
    Requires(Acc(spkt.State(), 1/20))

@Pure
def extensions_match(next_hdr: int, hdrs: List[ExtensionHeader], packet: bytes, offset: int) -> bool:
    Requires(Acc(list_pred(hdrs)))
    Requires(Forall(hdrs, lambda e: (e.State(), [])))
    if len(hdrs) == 0:
        return next_hdr not in L4Proto.L4
    return False

@Pure
def extension_len(hdrs: List[ExtensionHeader]) -> int:
    Requires(Acc(list_pred(hdrs)))
    Requires(Forall(hdrs, lambda e: (e.State(), [])))
    return extension_len_rec(hdrs, 0)

@Pure
def extension_len_rec(hdrs: List[ExtensionHeader], index: int) -> int:
    Requires(Acc(list_pred(hdrs)))
    Requires(Forall(hdrs, lambda e: (e.State(), [])))
    Requires(index >= 0 and index <= len(hdrs))
    if index == len(hdrs):
        return 0
    current = hdrs[index]  # type: ExtensionHeader
    return Unfolding(current.State(), current._hdr_len) + extension_len_rec(hdrs, index + 1)

def build_base_hdrs(src: SCIONAddr, dst: SCIONAddr, l4: int =L4Proto.UDP) -> Tuple[SCIONCommonHdr, SCIONAddrHdr]:
    ...
