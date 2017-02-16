from lib.packet.ext_hdr import HopByHopExtension


class SibraExtBase(HopByHopExtension):
    def __init__(self, raw=None):  # pragma: no cover
        # Flags (except request flag):
        self.accepted = True
        self.error = False