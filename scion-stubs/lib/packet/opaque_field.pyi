from lib.packet.packet_base import Serializable
from lib.defines import OPAQUE_FIELD_LEN
from lib.util import Raw


class OpaqueField(Serializable):
    LEN = OPAQUE_FIELD_LEN


class OpaqueFieldList(object):
    pass


class HopOpaqueField(OpaqueField):
    NAME = "HopOpaqueField"
    MAC_LEN = 3  # MAC length in bytes.
    MAC_BLOCK_LEN = 16

    def __init__(self, raw: Raw=None) -> None:  # pragma: no cover
        self.xover = False
        self.verify_only = False
        self.forward_only = False
        self.recurse = False
        self.exp_time = 0
        self.ingress_if = 0
        self.egress_if = 0
        self.mac = bytes(self.MAC_LEN)

    def calc_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> None:
        ...

    def set_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bytes:
        ...

    def verify_mac(self, key: bytes, ts: int, prev_hof:'HopOpaqueField'=None) -> bytes:  # pragma: no cover
        ...

    @classmethod
    def from_values(cls, exp_time: int, ingress_if: int=0, egress_if: int=0,
                    mac: bytes=None, xover: bool=False, verify_only: bool=False,
                    forward_only: bool=False, recurse: bool=False) -> HopOpaqueField:
        ...


class InfoOpaqueField(OpaqueField):
    def __init__(self) -> None:  # pragma: no cover
        self.up_flag = False
        self.shortcut = False
        self.peer = False
        self.timestamp = 0
        self.isd = 0
        self.hops = 0