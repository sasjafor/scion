from typing import NamedTuple, cast

from nagini_contracts.adt import ADT
from nagini_contracts.contracts import Sequence

from lib.packet.opaque_field import OpaqueFieldList, InfoOpaqueField, HopOpaqueField
from lib.packet.scion import SCIONL4Packet

"""
This is a set of classes based on the ADT basetype from Nagini to model a SCION packet in an abstract way.
"""


class ADT_HostAddrBase(ADT, NamedTuple('ADT_HostAddrBase', [('TYPE', int), ('addr', bytes)])):
    """
    Constructor for ADT_HostAddrBase
    """


class ADT_ISD_AS(ADT, NamedTuple('ADT_ISD_AS', [('_isd', int), ('_as', int)])):
    """
    Constructor for ADT_ISD_AS
    """
    pass


class ADT_OpaqueField(ADT, NamedTuple('ADT_OpaqueField', [])):
    """
    Constructor for ADT_OpaqueField
    """
    pass


class ADT_HOF(ADT_OpaqueField, NamedTuple('ADT_HOF', [('xover', bool), ('verify_only', bool), ('forward_only', bool),
                                                      ('exp_time', int), ('ingress_if', int), ('egress_if', int)])):
    """
    Constructor for ADT_HOF
    """
    pass


class ADT_IOF(ADT_OpaqueField, NamedTuple('ADT_IOF',
                                          [('up_flag', bool), ('shortcut', bool), ('peer', bool), ('timestamp', int),
                                           ('hops', int)])):
    """
    Constructor for ADT_IOF
    """
    pass


class ADT_Address(ADT, NamedTuple('ADT_Address', [('isd_as', ADT_ISD_AS), ('host', ADT_HostAddrBase)])):
    """
    Constructor for ADT_Address
    """
    pass


class ADT_AddrHdr(ADT, NamedTuple('ADT_AddrHdr', [('src', ADT_Address), ('dst', ADT_Address), ('_total_len', int)])):
    """
    Constructor for ADT_AddrHdr
    """
    pass


class ADT_Path(ADT, NamedTuple('ADT_Path',
                               [('A_HOFS', str), ('B_HOFS', str), ('C_HOFS', str), ('_ofs', Sequence[ADT_OpaqueField]),
                                ('_iof_idx', int), ('_hof_idx', int)])):
    """
    Constructor for ADT_Path
    """
    pass


class ADT_Packet(ADT, NamedTuple('ADT_Packet', [('addrs', ADT_AddrHdr), ('path', ADT_Path)])):
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


def map_ofs_list(ofs: OpaqueFieldList, iof_idx: int) -> Sequence[ADT_OpaqueField]:
    """
    Method to map the InfoOpaqueField and the HopOpaqueFields from the packet to a Nagini Sequence
    :param ofs: OpaqueFields from the packet
    :param iof_idx: index of the InfoOpaqueField that precedes the HopOpaqueFields
    :return: sequence of OpaqueField ADTs
    """
    res = Sequence()
    iof = iof_to_adt(cast(InfoOpaqueField, ofs.get_by_idx(iof_idx)))
    res.__add__(iof)
    i = iof_idx + 1
    while i <= iof_idx + iof.hops:
        hof = hof_to_adt(cast(HopOpaqueField, ofs.get_by_idx(i)))
        res.__add__(hof)
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

    ofs_seq = map_ofs_list(pkt_path._ofs, pkt_path._iof_idx)

    addrs = ADT_AddrHdr(src, dst, pkt_addrs._total_len)
    path = ADT_Path(pkt_path.A_HOFS, pkt_path.B_HOFS, pkt_path.C_HOFS, ofs_seq, pkt_path._iof_idx, pkt_path._hof_idx)

    return ADT_Packet(addrs, path)
