from lib.packet.ext_hdr import HopByHopExtension
from lib.util import Raw

class SibraExtBase(HopByHopExtension):
    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        # Flags (except request flag):
        self.accepted = True
        self.error = False