from typing import Tuple

from nagini_contracts.contracts import Requires, Ensures, Acc
from nagini_contracts.obligations import MustTerminate


class SCIONBaseException(Exception):
    """
    Root SCION Exception. All other exceptions derive from this.

    It should probably not be raised directly.
    """
    def __init__(self, *args: object) -> None:
        Requires(MustTerminate(1))
        Ensures(Acc(self.args_))
        self.args_ = args # type: Tuple[object, ...]


class SCIONBaseError(SCIONBaseException):
    """
    Root SCION Error exception. All other error exceptions derive from this.

    It should probably not be raised directly.
    """


class SCIONIOError(SCIONBaseError):
    """IO error"""


class SCIONIndexError(SCIONBaseError):
    """Index error (accessing out of bound index on array)"""


class SCIONKeyError(SCIONBaseError):
    """Key error (trying to access invalid entry in dictionary)"""


class SCIONJSONError(SCIONBaseError):
    """JSON parsing error"""


class SCIONYAMLError(SCIONBaseError):
    """YAML parsing error"""


class SCIONParseError(SCIONBaseError):
    """Parsing error"""


class SCIONTypeError(SCIONBaseError):
    """Wrong type"""


class SCIONServiceLookupError(SCIONBaseError):
    """Service lookup failed"""


class SCIONChecksumFailed(SCIONBaseError):
    """Checksum failed"""


class SCIONTCPError(SCIONBaseError):
    """SCION TCP error"""


class SCIONTCPTimeout(SCIONBaseError):
    """SCION TCP timeout"""
