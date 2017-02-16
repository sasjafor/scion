from lib.packet.ext_hdr import HopByHopExtension
from lib.types import ExtHopByHopType


class SCMPExt(HopByHopExtension):  # pragma: no cover
    NAME = "SCMPExt"
    EXT_TYPE = ExtHopByHopType.SCMP
    LEN = 5

    def __init__(self) -> None:
        self.error = True
        self.hopbyhop = False