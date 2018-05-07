from lib.packet.host_addr import HostAddrBase
from lib.packet.scion_addr import ISD_AS
from typing import Optional, List, Dict
from nagini_contracts.contracts import *


class Element(object):
    def __init__(self, port: int=None) -> None:
        self.addr = None  # type: Optional[HostAddrBase]
        self.port = port
        self.name = None  # type: Optional[str]

    @Predicate
    def State(self) -> bool:
        return Acc(self.addr)


class Topology(object):
    def __init__(self) -> None:  # pragma: no cover
        self.is_core_as = False
        self.mtu = None  # type: Optional[int]
        self.isd_as = None  # type: Optional[ISD_AS]
        self.beacon_servers = [] # type: List[RouterElement]
        self.certificate_servers = [] # type: List[RouterElement]
        self.path_servers = [] # type: List[RouterElement]
        self.sibra_servers = [] # type: List[RouterElement]

    @Predicate
    def State(self) -> bool:
        return Acc(self.is_core_as) and Acc(self.mtu) and Acc(self.isd_as)

    @classmethod
    def from_file(cls, topology_file: str) -> 'Topology':
        ...

    def get_own_config(self, server_type: str, server_id: str) -> Element:
        ...

    def get_all_border_routers(self) -> List[RouterElement]:
        ...


class InterfaceElement(Element):
    """
    The InterfaceElement class represents one of the interfaces of an border
    router.

    :ivar int if_id: the interface ID.
    :ivar int isd_as: the ISD-AS identifier of the neighbor AS.
    :ivar str link_type: the type of relationship to the neighbor AS.
    :ivar int to_udp_port:
        the port number receiving UDP traffic on the other end of the link.
    :ivar int udp_port: the port number used to send UDP traffic.
    """
    def __init__(self, interface_dict: Dict[str, object]) -> None:
        """
        :param dict interface_dict: contains information about the interface.
        """
        # super().__init__(interface_dict['Addr'], name)
        self.isd_as = 0
        self.if_id = 0
        self.udp_port = 0
        self.bandwidth = 0
        self.to_addr = None  # type: Optional[HostAddrBase]
        self.link_type = None  # type: Optional[str]
        self.to_udp_port = 0

    @Predicate
    def State(self) -> bool:
        return (Acc(self.isd_as) and
                Acc(self.if_id) and
                Acc(self.udp_port) and
                Acc(self.bandwidth) and
                Acc(self.to_addr) and
                Acc(self.link_type) and
                Acc(self.to_udp_port))


class RouterElement(Element):
    """
    The RouterElement class represents one of the border routers.
    """
    def __init__(self, router_dict: Dict[str, object]) -> None:  # pragma: no cover
        """
        :param dict router_dict: contains information about an border router.
        :param str name: router element name or id
        """
        self.interface = InterfaceElement({})
