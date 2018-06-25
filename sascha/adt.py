from typing import NamedTuple, List

from nagini_contracts.adt import ADT

class ADT_HostAddrBase(ADT):

class ADT_ISD_AS(ADT):

class ADT_OpaqueField(ADT, NamedTuple('ADT_OpaqueField', [])):
    """
    Constructor for ADT_OpaqueField
    """
    pass

class ADT_HOF(ADT_OpaqueField, NamedTuple('ADT_HOF', [('xover', bool), ('verify_only', bool), ('forward_only', bool), ('exp_time', int), ('ingress_if', int), ('egress_if', int)])):
    """
    Constructor for ADT_HOF
    """
    pass

class ADT_IOF(ADT_OpaqueField, NamedTuple('ADT_IOF', [('up_flag', bool), ('shortcut', bool), ('peer', bool), ('timestamp', int), ('hops', int)])):
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

class ADT_Path(ADT, NamedTuple('ADT_Path', [('A_HOFS', str), ('B_HOFS', str), ('C_HOFS', str), ('_ofs', List[ADT_OpaqueField]), ('_iof_idx', int), ('_hof_idx', int)])):
    """
    Constructor for ADT_Path
    """
    pass

class ADT_packet(ADT, NamedTuple('ADT_packet', [('addrs', ADT_AddrHdr), ('path', ADT_Path)])):
    """
    Constructor for ADT_packet
    """
    pass