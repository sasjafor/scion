from nagini_contracts.contracts import Predicate, Acc

from lib.packet.path_mgmt.rev_info import RevocationInfo


class InterfaceState:
    def __init__(self) -> None:
        self.is_active = True
        self.rev_info = None # type: RevocationInfo

    @Predicate
    def State(self) -> bool:
        return Acc(self.is_active) and Acc(self.rev_info)