from typing import NamedTuple, cast

from nagini_contracts.adt import ADT
from nagini_contracts.contracts import Sequence

from lib.packet.opaque_field import OpaqueFieldList, InfoOpaqueField, HopOpaqueField
from lib.packet.scion import SCIONL4Packet

"""
This is a set of classes based on the ADT basetype from Nagini to model a SCION packet in an abstract way.
"""

class ADT_base(ADT):
    """
    This is the base class for this ADT structure
    """
    pass

class ADT_HostAddrBase(ADT_base, NamedTuple('ADT_HostAddrBase', [('TYPE', int), ('addr', bytes)])):
    """
    Constructor for ADT_HostAddrBase
    """
    pass


class ADT_ISD_AS(ADT_base, NamedTuple('ADT_ISD_AS', [('isd', int), ('as', int)])):
    """
    Constructor for ADT_ISD_AS
    """
    pass

class ADT_HOF(ADT_base, NamedTuple('ADT_HOF', [('xover', bool), ('verify_only', bool), ('forward_only', bool), ('exp_time', int), ('ingress_if', int), ('egress_if', int)])):
    """
    Constructor for ADT_HOF
    """
    pass


class ADT_IOF(ADT_base, NamedTuple('ADT_IOF', [('up_flag', bool), ('shortcut', bool), ('peer', bool), ('timestamp', int), ('hops', int)])):
    """
    Constructor for ADT_IOF
    """
    pass


class ADT_Address(ADT_base, NamedTuple('ADT_Address', [('isd_as', ADT_ISD_AS), ('host', ADT_HostAddrBase)])):
    """
    Constructor for ADT_Address
    """
    pass


class ADT_AddrHdr(ADT_base, NamedTuple('ADT_AddrHdr', [('src', ADT_Address), ('dst', ADT_Address), ('total_len', int)])):
    """
    Constructor for ADT_AddrHdr
    """
    pass


class ADT_Path(ADT_base, NamedTuple('ADT_Path',
                               [('A_HOFS', str), ('B_HOFS', str), ('C_HOFS', str), ('iof', ADT_IOF), ('hofs', Sequence[ADT_HOF]),
                                ('iof_idx', int), ('hof_idx', int)])):
    """
    Constructor for ADT_Path
    """
    pass


class ADT_Packet(ADT_base, NamedTuple('ADT_Packet', [('addrs', ADT_AddrHdr), ('path', ADT_Path)])):
    """
    Constructor for ADT_packet
    """
    pass


def iof_to_adt(iof: InfoOpaqueField) -> ADT_IOF:
    """
    Method to map a InfoOpaqueField to an ADT
    :param iof: the original IOF
    :return: ADT containing the same information
    """
    return ADT_IOF(iof.up_flag, iof.shortcut, iof.peer, iof.timestamp, iof.hops)


def hof_to_adt(hof: HopOpaqueField) -> ADT_HOF:
    """
    Method to map a HopOpaqueField to an ADT
    :param hof: the original HOF
    :return: ADT containing the same information
    """
    return ADT_HOF(hof.xover, hof.verify_only, hof.forward_only, hof.exp_time, hof.ingress_if, hof.egress_if)


def map_ofs_list(ofs: OpaqueFieldList, iof_idx: int, iof: ADT_IOF) -> Sequence[ADT_HOF]:
    """
    Method to map the InfoOpaqueField and the HopOpaqueFields from the packet to a Nagini Sequence
    :param ofs: OpaqueFields from the packet
    :param iof_idx: index of the InfoOpaqueField that precedes the HopOpaqueFields
    :return: sequence of OpaqueField ADTs
    """
    res = Sequence() # type: Sequence[ADT_HOF]
    # iof = iof_to_adt(cast(InfoOpaqueField, ofs.get_by_idx(iof_idx)))
    # res.__add__(Sequence(iof))
    i = iof_idx + 1
    while i <= iof_idx + iof.hops:
        hof = hof_to_adt(cast(HopOpaqueField, ofs.get_by_idx(i)))
        res.__add__(Sequence(hof))
    return res


def map_scion_packet_to_adt(packet: SCIONL4Packet) -> ADT_Packet:
    """
    Method to map a SCIONPacket to the ADT defined in this file
    :param packet: the packet to be mapped
    :return: ADT containing the same information as the packet
    """
    pkt_addrs = packet.addrs
    pkt_path = packet.path
    pkt_addrs_src = packet.addrs.src
    pkt_addrs_dst = packet.addrs.dst
    pkt_addrs_src_isd_as = pkt_addrs_src.isd_as
    pkt_addrs_dst_isd_as = pkt_addrs_dst.isd_as
    pkt_addrs_src_host = pkt_addrs_src.host
    pkt_addrs_dst_host = pkt_addrs_dst.host

    src_isd_as = ADT_ISD_AS(pkt_addrs_src_isd_as._isd, pkt_addrs_src_isd_as._as)
    dst_isd_as = ADT_ISD_AS(pkt_addrs_dst_isd_as._isd, pkt_addrs_dst_isd_as._as)

    src_host = ADT_HostAddrBase(pkt_addrs_src_host.TYPE, pkt_addrs_src_host.addr)
    dst_host = ADT_HostAddrBase(pkt_addrs_dst_host.TYPE, pkt_addrs_dst_host.addr)

    src = ADT_Address(src_isd_as, src_host)
    dst = ADT_Address(dst_isd_as, dst_host)

    ofs = pkt_path._ofs
    iof_idx = pkt_path._iof_idx

    iof = iof_to_adt(cast(InfoOpaqueField, ofs.get_by_idx(iof_idx)))
    ofs_seq = map_ofs_list(ofs, iof_idx, iof)

    addrs = ADT_AddrHdr(src, dst, pkt_addrs._total_len)
    path = ADT_Path(pkt_path.A_HOFS, pkt_path.B_HOFS, pkt_path.C_HOFS, iof, ofs_seq, pkt_path._iof_idx, pkt_path._hof_idx)

    return ADT_Packet(addrs, path)
