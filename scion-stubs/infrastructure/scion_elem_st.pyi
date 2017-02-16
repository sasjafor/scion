from lib.topology import Topology
from lib.config import Config
from lib.packet.host_addr import HostAddrBase
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion import SCIONL4Packet, SCIONBasePacket
from lib.packet.scmp.errors import SCMPError
from lib.util import Raw
from lib.topology import RouterElement
from typing import Optional, Callable



class SCIONElement(object):
    def __init__(self, server_id: str, conf_dir: str,
                 host_addr: HostAddrBase=None, port: int=None) -> None:
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param `HostAddrBase` host_addr:
            the interface to bind to. Overrides the address in the topology
            config.
        :param int port:
            the port to bind to. Overrides the address in the topology config.
        """
        self.id = server_id
        self.conf_dir = conf_dir
        self.ifid2br = {}  # type: Dict[int, RouterElement]
        self._port = port
        self.topology = None  # type: Topology
        self.config = None  # type: Config
        self.addr = None  # type: SCIONAddr

    def _parse_packet(self, packet: Raw) -> Optional[SCIONL4Packet]:
        pass

    def _scmp_validate_error(self, pkt: SCIONBasePacket, e: SCMPError) -> None:
        ...

    def _get_handler(self, pkt: SCIONL4Packet) -> Optional[Callable[[SCIONL4Packet, bool], None]]:
        ...