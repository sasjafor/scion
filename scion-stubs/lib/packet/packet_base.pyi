

class Serializable:
    pass


class Cerealizable:
    pass


class SCIONPayloadBaseProto(Cerealizable):
    pass


class PacketBase(Serializable):
    pass


class PayloadBase(Serializable):  # pragma: no cover
    METADATA_LEN = 0