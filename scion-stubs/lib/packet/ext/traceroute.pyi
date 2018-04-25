from nagini_contracts.contracts import ContractOnly

from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.scion_addr import ISD_AS


class TracerouteExt(HopByHopExtension):

    # @ContractOnly
    # def append_hop(self, isd_as: ISD_AS, if_id: int, timestamp: int=None) -> None:  # pragma: no cover
        pass
