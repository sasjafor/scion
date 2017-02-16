from lib.packet.packet_base import L4HeaderBase
from lib.types import L4Proto


class SCIONUDPHeader(L4HeaderBase):
    """
    Encapsulates the UDP header for UDP/SCION packets.
    """
    LEN = 8
    TYPE = L4Proto.UDP
    NAME = "SCIONUDPHeader"
    CHKSUM_LEN = 2