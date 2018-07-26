from lib.errors import SCIONBaseError, SCIONBaseException


class SCIONIFVerificationError(SCIONBaseError):
    """
    The current hop field (ingress or egress, depending on context) interface
    does not match the interface of the border router.
    """


class SCIONOFVerificationError(SCIONBaseError):
    """
    Opaque field MAC verification error.
    """
    pass


class SCIONOFExpiredError(SCIONBaseError):
    """
    Opaque field expired error.
    """
    pass


class SCIONPacketHeaderCorruptedError(SCIONBaseError):
    """
    Packet header is in an invalid state.
    """
    pass


class SCIONInterfaceDownException(SCIONBaseException):
    """
    The interface to forward the packet to is down.
    """
    def __init__(self, if_id: int) -> None:
        super().__init__()
        self.if_id = if_id


class SCIONSegmentSwitchError(SCIONBaseException):
    """
    Switching from previous to current segment is disallowed.
    """