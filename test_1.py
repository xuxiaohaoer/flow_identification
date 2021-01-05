import dpkt
import os
from pre import *

SSL3_VERSION_BYTES = set((b'\x03\x00', b'\x03\x01', b'\x03\x02', b'\x03\x03'))
class TLSRecord(dpkt.Packet):

    """
    SSLv3 or TLSv1+ packet.

    In addition to the fields specified in the header, there are
    compressed and decrypted fields, indicating whether, in the language
    of the spec, this is a TLSPlaintext, TLSCompressed, or
    TLSCiphertext. The application will have to figure out when it's
    appropriate to change these values.
    """

    __hdr__ = (
        ('type', 'B', 0),
        ('version', 'H', 0),
        ('length', 'H', 0),
    )

    def __init__(self, *args, **kwargs):
        # assume plaintext unless specified otherwise in arguments
        self.compressed = kwargs.pop('compressed', False)
        self.encrypted = kwargs.pop('encrypted', False)
        # parent constructor
        dpkt.Packet.__init__(self, *args, **kwargs)
        # make sure length and data are consistent
        self.length = len(self.data)

    def unpack(self, buf):
        dpkt.Packet.unpack(self, buf)
        header_length = self.__hdr_len__
        self.data = buf[header_length:header_length + self.length]
        # make sure buffer was long enough
        if len(self.data) != self.length:
            raise dpkt.NeedData('TLSRecord data was too short.')
        # assume compressed and encrypted when it's been parsed from
        # raw data
        self.compressed = True
        self.encrypted = True

class SSL3Exception(Exception):
    pass

def tls_multi_factory(buf):
    """
    Attempt to parse one or more TLSRecord's out of buf

    Args:
      buf: string containing SSL/TLS messages. May have an incomplete record
        on the end

    Returns:
      [TLSRecord]
      int, total bytes consumed, != len(buf) if an incomplete record was left at
        the end.

    Raises SSL3Exception.
    """
    i, n = 0, len(buf)
    msgs = []
    while i + 5 <= n:
        v = buf[i + 1:i + 3]
        #  version
        if v in SSL3_VERSION_BYTES:
            try:
                msg = TLSRecord(buf[i:])
                msgs.append(msg)
            except dpkt.NeedData:
                break
        else:
            raise SSL3Exception('Bad TLS version in buf: %r' % buf[i:i + 5])
        i += len(msg)
    return msgs, i


def main():


    base_dir = "data/资格赛数据分析/"
    for file in os.listdir(base_dir):
        file = "192.168.10.91.pcap"
        dir = base_dir + file
        try:
            with open(dir, 'rb') as f:
                print(file)
                capture = dpkt.pcap.Reader(f)
                nth = 0
                for timestamp, packet in capture:
                    nth += 1
                    if nth == 6 :
                        eth = dpkt.ethernet.Ethernet(packet)
                        if isinstance(eth.data, dpkt.ip.IP):
                            ip = eth.data
                            # parse_ip_packet(eth,nth, timestamp)
                            if isinstance(ip.data, dpkt.tcp.TCP):
                                tcp_data = ip.data
                                stream = tcp_data.data
                                if len(stream):
                                    if stream[0] in {20,21,22}:
                                        try:
                                            records, bytes_used = tls_multi_factory(stream)
                                            print(nth, records)
                                        except:
                                            print('{}error'.format(nth))
                f.close()
        except:
            pass


if __name__ == "__main__":
    print("begin")
    main()