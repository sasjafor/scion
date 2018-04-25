from typing import List, Tuple

from nagini_contracts.contracts import ContractOnly

from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.scion import SCIONL4Packet
from lib.sibra.state.state import SibraState
from lib.util import Raw

class SibraExtBase(HopByHopExtension):
    def __init__(self, raw:Raw=None) -> None:  # pragma: no cover
        # Flags (except request flag):
        self.accepted = True
        self.error = False

    @ContractOnly
    def process(self, state: SibraState, spkt: SCIONL4Packet, from_local_as: bool, key: bytes) -> List[Tuple[int, str]]:
        pass
