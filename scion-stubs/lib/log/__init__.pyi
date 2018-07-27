import logging

from nagini_contracts.contracts import Requires
from nagini_contracts.obligations import MustTerminate


def log_exception(msg: str, level: int  = logging.CRITICAL) -> None:
    Requires(MustTerminate(1))
    ...