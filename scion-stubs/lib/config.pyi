class Config(object):
    def __init__(self) -> None:  # pragma: no cover
        self.master_as_key = 0
        self.propagation_time = 0
        self.registration_time = 0
        self.registers_paths = 0
        self.cert_ver = 0

    @classmethod
    def from_file(cls, config_file: str) -> 'Config':
        ...