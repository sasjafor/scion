from nagini_contracts.contracts import ContractOnly


@ContractOnly
def crc32(data: bytes) -> int:
    ...