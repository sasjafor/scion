from lib.packet.path_mgmt.base import PathMgmtPayloadBase


class RevocationInfo(PathMgmtPayloadBase):
    @staticmethod
    def from_raw(raw: bytes) -> 'RevocationInfo':
        ...