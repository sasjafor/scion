from typing import Generic, TypeVar, Dict, Type

from nagini_contracts.contracts import Pure, ContractOnly, Requires, Ensures, Implies, Result, dict_pred, Rd

T = TypeVar('T')
V = TypeVar('V')

class defaultdict(Generic[T, V], Dict[T, V]):
    def __init__(self, df: Type[V]) -> None:
        ...

    @Pure
    @ContractOnly
    def __getitem__(self, item: T) -> V:
        Requires(Rd(dict_pred(self)))
        Ensures(Implies(super().__contains__(item), Result() is super().__getitem__(item)))