from lib.packet.path_mgmt.rev_info import RevocationInfo


class InterfaceState:
    def __init__(self) -> None:
        self.is_active = True
        self.rev_info = None # type: RevocationInfo