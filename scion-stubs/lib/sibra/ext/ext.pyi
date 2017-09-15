from lib.packet.ext_hdr import HopByHopExtension
from lib.util import Raw
from typing import List, Tuple

class SibraExtBase(HopByHopExtension):
    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        # Flags (except request flag):
        self.accepted = True
        self.error = False

    def process(self, state, spkt, from_local_as, key) -> List[Tuple[int, str]]:
        ...