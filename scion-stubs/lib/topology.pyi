from lib.packet.host_addr import HostAddrBase
from lib.packet.scion_addr import ISD_AS
from typing import Optional, List


class Element(object):
    def __init__(self, port: int=None) -> None:
        self.addr = None  # type: Optional[HostAddrBase]
        self.port = port
        self.name = None  # type: Optional[str]


class Topology(object):
    def __init__(self) -> None:  # pragma: no cover
        self.is_core_as = False
        self.mtu = None  # type: Optional[int]
        self.isd_as = None  # type: Optional[ISD_AS]

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
    def __init__(self, interface_dict) -> None:
        """
        :param dict interface_dict: contains information about the interface.
        """
        # super().__init__(interface_dict['Addr'], name)
        self.isd_as = None  # type: Optional[int]
        self.if_id = None  # type: Optional[int]
        self.udp_port = None  # type: Optional[int]
        self.bandwidth = None  # type: Optional[int]
        self.to_addr = None  # type: Optional[HostAddrBase]


class RouterElement(Element):
    """
    The RouterElement class represents one of the border routers.
    """
    def __init__(self, router_dict) -> None:  # pragma: no cover
        """
        :param dict router_dict: contains information about an border router.
        :param str name: router element name or id
        """
        self.interface = None # type: InterfaceElement
