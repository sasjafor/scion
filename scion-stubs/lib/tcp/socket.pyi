

class SCIONTCPSocket(object):
    pass


class SockOpt(object):
    # LWIP's socket options.
    SOF_ACCEPTCONN = 0x02  # socket has had listen()
    SOF_REUSEADDR = 0x04  # allow local address reuse
    SOF_KEEPALIVE = 0x08  # keep connections alive
    SOF_BROADCAST = 0x20  # permit to send and to receive broadcast messages
    SOF_LINGER = 0x80  # linger on close if data present, PSz: unimplemented