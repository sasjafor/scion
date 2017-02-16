

class ExpiringDict(dict):
    def __init__(self, max_len: int, max_age_seconds: int) -> None:
        ...
