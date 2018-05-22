from typing import Optional
from nagini_contracts.contracts import *

class Serializable:
    pass


class Cerealizable:

    def copy(self) -> Cerealizable:
        ...


class SCIONPayloadBaseProto(Cerealizable):
    pass


class PacketBase(Serializable):
    def get_payload(self) -> bytes:
        ...


class PayloadBase(Serializable):  # pragma: no cover
    METADATA_LEN = 0


class L4HeaderBase(Serializable):
    TYPE = None  # type: Optional[int]

    @Predicate
    def State(self) -> bool:
        return True

    @Pure
    def matches(self, raw: bytes, offset: int) -> bool:
        return True


class PayloadRaw(PayloadBase):  # pragma: no cover
    SNIPPET_LEN = 32