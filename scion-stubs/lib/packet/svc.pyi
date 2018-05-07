from typing import Dict

from lib.packet.host_addr import HostAddrSVC


class SVCType:
    pass


SVC_TO_SERVICE = {}  # type: Dict[object, str]


SERVICE_TO_SVC_A = {}  # type: Dict[str, HostAddrSVC]
