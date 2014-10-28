import dpkt


class RMCP(dpkt.Packet):
    __hdr__ = (
        ('version', 'B', 0x06),
        ('null', 'B', 0x00),
        ('sequence', 'B', 0xff),
        ('_type_class', 'B', 0x06),
        )

    def __repr__(self):
        return super(RMCP, self).__repr__(pclass=self.pclass, type=self.type)

    def pack_hdr(self):
        self._type_class = (self.type << 7) | self.pclass
        return super(RMCP, self).pack_hdr()

    def unpack(self, buf):
        super(RMCP, self).unpack(buf)
        self.type = self._type_class >> 7  # aliasing this name isn't ideal
        self.pclass = self._type_class & 0x1f
        if self.pclass == 0x07:
            try:
                if self.data.startswith('\x00'):
                    self.data = IPMISessionWrapper(self.data)
                else:
                    self.data = IPMIAuthenticatedSessionWrapper(self.data)
            except (KeyError, dpkt.UnpackError):
                pass


class IPMISessionWrapper(dpkt.Packet):
    """ IPMI v1.5 Session Wrapper """
    __hdr__ = (
        ('auth_type', 'B', 0x00),
        ('session_sequence', 'I', 0x00000000),
        ('session_id', 'I', 0x00000000),
        ('message_len', 'B', 0x00),
        )

    def unpack(self, buf):
        super(IPMISessionWrapper, self).unpack(buf)
        try:
            self.data = IPMI(self.data)
        except (KeyError, dpkt.UnpackError):
            pass


class IPMIAuthenticatedSessionWrapper(IPMISessionWrapper):
    __hdr__ = (
        ('auth_type', 'B', 0x04),
        ('session_sequence', 'I', 0x00000000),
        ('session_id', 'I', 0x00000000),
        ('auth_code', '16s', '\x00' * 16),
        ('message_len', 'B', 0x00),
        )


class IPMI(dpkt.Packet):
    __hdr__ = (
        ('target_address', 'B', 0x20),
        ('_tlun_netfn', 'B', 0x00),
        ('checksum', 'B', 0x00),
        ('source_address', 'B', 0x00),
        ('_slun_ntfn', 'B', 0x00),
        ('cmd', 'B', 0x00),
        )

    def __init__(self, *args, **kwargs):
        self.data_checksum = 0x00
        return super(IPMI, self).__init__(*args, **kwargs)

    def __str__(self):
        return super(IPMI, self).__str__() + chr(self.data_checksum)

    def unpack(self, buf):
        """ Treat the data checksum as a header """
        super(IPMI, self).unpack(buf)
        self.data_checksum = ord(self.data[-1])
        self.data = self.data[:-1]
