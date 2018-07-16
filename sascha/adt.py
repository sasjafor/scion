from typing import NamedTuple, cast, Optional

from nagini_contracts.adt import ADT
from nagini_contracts.contracts import Sequence, Requires, Acc, Pure, Ensures, Invariant, Unfolding, Unfold, Fold
from nagini_contracts.obligations import MustTerminate

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

class ADT_HostAddrBase(ADT_base, NamedTuple('ADT_HostAddrBase', [('TYPE', Optional[int]), ('addr', Optional[bytes])])):
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

@Pure
def iof_to_adt(iof: InfoOpaqueField) -> ADT_IOF:
    Requires(Acc(iof.State(), 1/10))
    """
    Method to map a InfoOpaqueField to an ADT
    :param iof: the original IOF
    :return: ADT containing the same information
    """
    return ADT_IOF(iof.get_up_flag(), iof.get_shortcut(), iof.get_peer(), iof.get_timestamp(), iof.get_hops())

@Pure
def hof_to_adt(hof: HopOpaqueField) -> ADT_HOF:
    Requires(Acc(hof.State(), 1/10))
    """
    Method to map a HopOpaqueField to an ADT
    :param hof: the original HOF
    :return: ADT containing the same information
    """
    return ADT_HOF(hof.get_xover(), hof.get_verify_only(), hof.get_forward_only(), hof.get_exp_time(), hof.get_ingress_if(), hof.get_egress_if())

@Pure
def map_ofs_list_rec(seq: Sequence[ADT_HOF], ofs: OpaqueFieldList, curr_idx: int, last_idx: int) -> Sequence[ADT_HOF]:
    Requires(Acc(ofs.State(), 1/10))
    Requires(last_idx < ofs.get_len())
    Requires(curr_idx >= 0)
    Requires(curr_idx <= last_idx)
    Requires(curr_idx < ofs.get_len())
    """
    Method to map the InfoOpaqueField and the HopOpaqueFields from the packet to a Nagini Sequence
    :param ofs: OpaqueFields from the packet
    :param iof_idx: index of the InfoOpaqueField that precedes the HopOpaqueFields
    :return: sequence of OpaqueField ADTs
    """
    hof = ofs.get_hof_by_idx(curr_idx)
    hof_adt = Unfolding(Acc(ofs.State(), 1/10), hof_to_adt(hof))
    hof_seq = Sequence(hof_adt) # type: Sequence[ADT_HOF]
    res = seq.__add__(hof_seq)
    if curr_idx == last_idx:
        return res
    return map_ofs_list_rec(res, ofs, curr_idx + 1, last_idx)

@Pure
def map_ofs_list(ofs: OpaqueFieldList, iof_idx: int, iof: ADT_IOF) -> Sequence[ADT_HOF]:
    Requires(Acc(ofs.State(), 1 / 10))
    Requires(iof.hops >= 0)
    Requires(iof_idx >= 0)
    Requires(iof_idx + iof.hops < ofs.get_len())
    """
    Method to map the InfoOpaqueField and the HopOpaqueFields from the packet to a Nagini Sequence
    :param ofs: OpaqueFields from the packet
    :param iof_idx: index of the InfoOpaqueField that precedes the HopOpaqueFields
    :return: sequence of OpaqueField ADTs
    """
    res = Sequence() # type: Sequence[ADT_HOF]
    if iof.hops == 0:
        return res
    return map_ofs_list_rec(res, ofs, iof_idx + 1, iof_idx + iof.hops)

def map_scion_packet_to_adt(pkt: SCIONL4Packet) -> ADT_Packet:
    Requires(Acc(pkt.State(), 1 / 10))
    Requires(pkt.get_path() is not None)
    # Requires(pkt.get_path_iof_idx() is not None)
    Requires(Unfolding(Acc(pkt.State(), 1 / 10), pkt.path.get_iof_idx() is not None))
    Requires(pkt.get_path_hof_idx() is not None)
    Ensures(Acc(pkt.State(), 1 / 10))
    """
    Method to map a SCIONPacket to the ADT defined in this file
    :param packet: the packet to be mapped
    :return: ADT containing the same information as the packet
    """

    iof_idx = pkt.get_path_iof_idx()

    Unfold(Acc(pkt.State(), 1 / 10))

    iof = pkt.path.get_iof()

    Unfold(Acc(pkt.path.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.src.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.dst.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.src.host.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.dst.host.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.src.isd_as.State(), 1 / 10))
    Unfold(Acc(pkt.addrs.dst.isd_as.State(), 1 / 10))

    src_isd_as = ADT_ISD_AS(pkt.addrs.src.isd_as._isd, pkt.addrs.src.isd_as._as)
    dst_isd_as = ADT_ISD_AS(pkt.addrs.dst.isd_as._isd, pkt.addrs.dst.isd_as._as)

    src_host = ADT_HostAddrBase(pkt.addrs.src.host.TYPE, pkt.addrs.src.host.addr)
    dst_host = ADT_HostAddrBase(pkt.addrs.dst.host.TYPE, pkt.addrs.dst.host.addr)

    src = ADT_Address(src_isd_as, src_host)
    dst = ADT_Address(dst_isd_as, dst_host)

    ofs = pkt.path._ofs

    # iof_adt = iof_to_adt(cast(InfoOpaqueField, pkt.path._ofs.get_by_idx(pkt.path._iof_idx)))
    iof_adt = iof_to_adt(iof)
    ofs_seq = map_ofs_list(ofs, iof_idx, iof_adt)

    addrs = ADT_AddrHdr(src, dst, pkt.addrs._total_len)
    path = ADT_Path(pkt.path.A_HOFS, pkt.path.B_HOFS, pkt.path.C_HOFS, iof_adt, ofs_seq, pkt.path._iof_idx, pkt.path._hof_idx)

    Fold(Acc(pkt.addrs.src.isd_as.State(), 1 / 10))
    Fold(Acc(pkt.addrs.dst.isd_as.State(), 1 / 10))
    Fold(Acc(pkt.addrs.src.host.State(), 1 / 10))
    Fold(Acc(pkt.addrs.dst.host.State(), 1 / 10))
    Fold(Acc(pkt.addrs.src.State(), 1 / 10))
    Fold(Acc(pkt.addrs.dst.State(), 1 / 10))
    Fold(Acc(pkt.addrs.State(), 1 / 10))
    Fold(Acc(pkt.path.State(), 1 / 10))
    Fold(Acc(pkt.State(), 1 / 10))

    return ADT_Packet(addrs, path)
