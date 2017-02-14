from lib.packet.packet_base import Serializable


class OpaqueField(Serializable):
    pass


class HopOpaqueField(OpaqueField):
    pass


class InfoOpaqueField(OpaqueField):
    pass