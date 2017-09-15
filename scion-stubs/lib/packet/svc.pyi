from lib.packet.host_addr import HostAddrSVC


class SVCType:
    BS_A = HostAddrSVC(0, raw=False)
    BS_M = HostAddrSVC(0 | HostAddrSVC.MCAST, raw=False)
    # Path service
    PS_A = HostAddrSVC(1, raw=False)
    # Certificate service
    CS_A = HostAddrSVC(2, raw=False)
    # SIBRA service
    SB_A = HostAddrSVC(3, raw=False)
    # No service, used e.g., in TCP socket.
    NONE = HostAddrSVC(0xffff, raw=False)


SVC_TO_SERVICE = {}  # type: Dict[object, str]


SERVICE_TO_SVC_A = {}  # type: Dict[str, HostAddrSVC]
