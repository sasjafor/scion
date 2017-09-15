from lib.packet.scmp.info import SCMPInfoRevocation
from lib.packet.packet_base import PayloadBase
from lib.util import Raw

class SCMPPayload(PayloadBase):
    NAME = "SCMPPayload"
    # Info len(1B), Cmn hdr len (1B), Addr hdr len (1B), Path hdr len (1B), Ext
    # hdrs len (1B), L4 hdr len (1B), L4 proto (1B)
    STRUCT_FMT = "!BBBBBBBx"

    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover

        self._cmn_hdr = b""
        self._addrs = b""
        self._path = b""
        self._exts = b""
        self._l4_hdr = b""
        self.info = SCMPInfoRevocation()