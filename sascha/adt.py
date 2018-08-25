from typing import NamedTuple, cast, Optional

from nagini_contracts.adt import ADT
from nagini_contracts.contracts import Sequence

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


class ADT_AddrHdr(ADT_base, NamedTuple('ADT_AddrHdr', [('src', ADT_Address), ('dst', ADT_Address), ('total_len', Optional[int])])):
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
