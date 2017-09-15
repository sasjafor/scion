class MetadataBase(object):
    def __init__(self):
        self.ia = None
        self.host = None
        self.path = None  # Ready for sending (i.e., in correct direction)
        self.port = 0
        self.ext_hdr = ()
        self.pkt = None




class RawMetadata(MetadataBase):
    def __init__(self):
        self.packet = None
        self.addr = None
        self.from_local_as = None


class SCMPMetadata(MetadataBase):
    pass


class SockOnlyMetadata(MetadataBase):
    pass


class TCPMetadata(MetadataBase):
    pass


class UDPMetadata(MetadataBase):
    @staticmethod
    def from_values(ia:object =None, host:object =None, path:object =None, ext_hdrs:object =(), port:int =0) -> 'UDPMetadata':
        ...