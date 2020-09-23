
from __future__ import absolute_import
from __future__ import print_function
import traceback
import argparse
import ipaddress
from binascii import hexlify
import socket
import struct
import sys
import dpkt
import textwrap
import os
from asn1crypto import x509
from dpkt import ssl, Packet
import pickle
from constants import PRETTY_NAMES
from cert_filter import CertFilter


global encrypted_streams
encrypted_streams = []  # change_cipher
global ssl_servers_certs
ssl_servers_certs = {}
global ssl_servers_with_client_hello
ssl_servers_with_client_hello = set()
global client_hello_set
client_hello_set = set()

global server_ip_set
server_ip_set = set()

global buffer
buffer = {}
need_more_parse = False


def tls_multi_factory_new(buf):
    """
    Attempt to parse one or more TLSRecord's out of buf
    :param buf: string containing SSL/TLS messages. May have an incomplete record on the end
    :return:  [TLSRecord] int, total bytes consumed, != len(buf) if an incomplete record was left at the end.
    Raises SSL3Exception.
    """
    i, n = 0, len(buf)
    msgs = []

    while i + 5 <= n:
        v = buf[i + 1:i + 3]
        if v in ssl.SSL3_VERSION_BYTES:
            try:
                msg = ssl.TLSRecord(buf[i:])
                msgs.append(msg)
            except dpkt.NeedData:
                break
        else:
            if i == 0:  ############################################ added
                raise ssl.SSL3Exception('Bad TLS version in buf: %r' % buf[i:i + 5])
            else:
                break

        i += len(msg)

    return msgs, i


class FlowDirection(object):
    OUT = 1
    IN = 2
    UNKNOWN = 3


class Extension(object):
    """
    Encapsulates TLS extensions.
    """

    def __init__(self, payload):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = pretty_name('extension_type', self._type_id)
        self._length, payload = unpacker('H', payload)
        # Data contains an array with the 'raw' contents
        self._data = None
        # pretty_data contains an array with the 'beautified' contents
        self._pretty_data = None
        if self._length > 0:
            self._data, self._pretty_data = parse_extension(payload[:self._length],
                                                            self._type_name)

    def __str__(self):
        # Prints out data array in textual format
        return '{0}: {1}'.format(self._type_name, self._pretty_data)


class OP:
    CHECK_TLS_PACKET = 1
    MERGE_TLS_PACKET = 2


def analyze_packet(_timestamp, packet, nth, op):
    """
    Main analysis loop for pcap.
    """
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        # print("timestamp:", _timestamp, "debug")
        parse_ip_packet(eth.data, nth, _timestamp, op)


def parse_arguments():
    """
    Parses command line arguments.
    """
    global filename
    global verboseprint
    global output_file
    global is_white_sample
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
Captures, parses and shows TLS Handshake packets
Copyright (C) 2015 Peter Mosmans [Go Forward]
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.'''))
    parser.add_argument('-r', '--read', metavar='FILE', action='store',
                        help='read from file (don\'t capture live packets)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='increase output verbosity')
    parser.add_argument('-t', '--is_white_sample', action='store_true',
                        help='is white sample?')
    parser.add_argument('-o', '--output', action='store',
                        help='output file')
    args = parser.parse_args()

    if args.verbose:
        def verboseprint(*args):
            print('# ', end="")
            for arg in args:
                print(arg, end="")
            print()
    else:
        verboseprint = lambda *a: None
    if args.is_white_sample:
        print("OK, process white sample data.")
        is_white_sample = True
    else:
        print("OK, process black sample data.")
        is_white_sample = False
    filename = None
    if args.read:
        filename = args.read
    output_file = "demo_output.pickle"
    if args.output:
        output_file = args.output


def parse_ip_packet(ip, nth, timestamp, op):
    """
    Parses IP packet.
    """
    sys.stdout.flush()
    if isinstance(ip.data, dpkt.tcp.TCP):
        # print("****TCP packet found****", "tcp payload:", list(ip.data.data))
        """
        try:
            tls = dpkt.ssl.TLS(ip.data.data)
            if len(tls.records) < 1:
                return
        except Exception as e:
            print(e)
            return
        """
        parse_tcp_packet(ip, nth, timestamp, op)


# TLS  version
def check_tls_version(data):
    version2 = False
    version3 = False

    if len(data) > 2:
        # ssl
        tmp = struct.unpack("bbb", data[0:3])
    else:
        return version2, version3

    # SSL v2. OR Message body too short.
    if (tmp[0] & 0x80 == 0x80) and (((tmp[0] & 0x7f) << 8 | tmp[1]) > 9):
        version2 = True
    elif (tmp[1] != 3) or (tmp[2] > 3):  # 版本,SSL 3.0 or TLS 1.0, 1.1 and 1.2
        version3 = False
    elif (tmp[0] < 20) or (tmp[0] > 23):  # 类型错误
        pass
    else:
        version3 = True

    return version2, version3


def parse_tcp_packet(ip, nth, timestamp, op):
    """
    Parses TCP packet.
    """
    record_server_ip(ip)
    stream = ip.data.data
    if len(stream):
        record_data_flow(ip, stream, nth, timestamp)


# def record_server_ip(ip):
#     """
# >>> int(ipaddress.IPv4Address('192.168.0.1'))
# 3232235521
# >>> int(ipaddress.IPv4Address('0.0.0.1'))
# 1
# >>> int(ipaddress.IPv4Address('0.0.1.1'))
# 257
#     """
#     src_ip = socket.inet_ntoa(ip.src)
#     dst_ip = socket.inet_ntoa(ip.dst)
#     # 这里使用一个确定规则（小ip作为源），把相同方向的数据汇聚到一起
#     if int(ipaddress.IPv4Address(src_ip)) < int(ipaddress.IPv4Address(dst_ip)):
#         connection_key = "{}-{}".format(dst_ip, src_ip)
#         global server_ip_set
#         if connection_key not in server_ip_set:
#             server_ip_set.add(connection_key)
#             buffer[connection_key] = [{"out":[], "in":[]}]


def record_server_ip(ip):
    src_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    dst_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    tcp = ip.data
    fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
    syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
    rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
    psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
    ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
    urg_flag = ( tcp.flags & dpkt.tcp.TH_URG ) != 0
    ece_flag = ( tcp.flags & dpkt.tcp.TH_ECE ) != 0
    cwr_flag = ( tcp.flags & dpkt.tcp.TH_CWR ) != 0
    # print("syn flag:{} ack flag:{} fin flag:{}".format(syn_flag, ack_flag, fin_flag))
    if syn_flag and ack_flag:
        # TCP SYN and ACK
        connection_key = "{}-{}".format(dst_ip, src_ip)
        global server_ip_set
        if connection_key not in server_ip_set:
            server_ip_set.add(connection_key)
            buffer[connection_key] = [{"out" :[], "in" :[]}]
        else:
            print("found multi flow!connection key:{}".format(connection_key))
            buffer[connection_key].append({"out" :[], "in" :[]})
    else:
        # What the fuck is it!!! TODO, why pcap has no SYN handshake 3 ???
        if  ip.data.data and ip.data.data[0] == 22:
            """ refer: The Transport Layer Security (TLS) Protocol URL:https://tools.ietf.org/html/rfc5246
            enum {
                  change_cipher_spec(20), alert(21), handshake(22),
                  application_data(23), (255)
              } ContentType;
            """
            connection_key = "{}-{}".format(src_ip, dst_ip)
            connection_key2 = "{}-{}".format(dst_ip, src_ip)
            if connection_key not in server_ip_set and connection_key2 not in server_ip_set:
                print \
                    ("Warning: found ssl with no 3-times handshake. I don't know why. But I will add it into buffer. connection:{}".format
                        (connection_key))
                server_ip_set.add(connection_key)
                buffer[connection_key] = [{"out" :[], "in" :[]}]


def has_application_data(flow_list):
    for flow in flow_list:
        if flow[0] == 23:
            return True
    return False


def record_data_flow(ip, stream, nth, timestamp):
    global buffer
    global server_ip_set
    src_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    dst_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    if "{}-{}".format(src_ip, dst_ip) in server_ip_set:  # OUT flow
        connection_key = "{}-{}".format(src_ip, dst_ip)
        buffer[connection_key][-1]["out"].append((stream[0], nth, timestamp, bytearray(stream)))
    elif "{}-{}".format(dst_ip, src_ip) in server_ip_set:  # IN flow
        connection_key = "{}-{}".format(dst_ip, src_ip)
        buffer[connection_key][-1]["in"].append((stream[0], nth, timestamp, bytearray(stream)))


def client_hello_ssl_v2(data):
    tmp = struct.unpack("bbb", data[0:3])
    if tmp[2] == 0x01:
        # Client_hello.
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        cipher_specs_size = (data[5] << 8) | data[6]
        if cipher_specs_size % 3 != 0:  # Cipher specs not a multiple of 3 bytes.
            return 0

        session_id_len = (data[7] << 8) | data[8]
        random_size = (data[9] << 8) | data[10]
        if lens < (9 + cipher_specs_size + session_id_len + random_size):
            return 0
        return lens + 2

    # if tmp[2] == 0x00:      # ERROR.
    #     ty = 0

    if tmp[2] == 0x04:
        # Server hello, Not processing
        lens = (tmp[0] & 0x7f) << 8 | tmp[1]
        return lens + 2

    return 0


def parse_tls_records(ip, stream, nth=None, need_certs=False):
    is_tls_v2, version3 = check_tls_version(stream)
    """
    Parses TLS Records.
          TLS Handshake

               +-----+                              +-----+
               |     |                              |     |
               |     |        ClientHello           |     |
               |     o----------------------------> |     |
               |     |                              |     |
       CLIENT  |     |        ServerHello           |     |  SERVER
               |     |       [Certificate]          |     |
               |     |    [ServerKeyExchange]       |     |
               |     |    [CertificateRequest]      |     |
               |     |      ServerHelloDone         |     |
               |     | <----------------------------o     |
               |     |                              |     |
               |     |       [Certificate]          |     |
               |     |     ClientKeyExchange        |     |
               |     |    [CertificateVerify]       |     |
               |     |   ** ChangeCipherSpec **     |     |
               |     |         Finished             |     |
               |     o----------------------------> |     |
               |     |                              |     |
               |     |   ** ChangeCipherSpec **     |     |
               |     |         Finished             |     |
               |     | <----------------------------o     |
               |     |                              |     |
               +-----+                              +-----+

 Optional messages
 --------------------------------------------------------------------------------------------
 Certificate (server)     needed with all key exchange algorithms, except for anonymous ones.
 ServerKeyExchange        needed in some cases, like Diffie-Hellman key exchange algorithm.
 CertificateRequest       needed if Client authentication is required.
 Certificate (client)     needed in response to CertificateRequest by the server.
 CertificateVerify        needed if client Certificate message was sent.
    """
    if nth:
        print("*" * 99)
        print("20 21 22 23 ??? SSL tcp payload(10):", list(stream[:10]), "nth:", nth)
    assert (stream[0]) in {20, 21, 22, 23}
    # print("Found reassembled segments data: {}".format(stream[0]))
    # print("SSL tcp payload:", list(stream))
    try:
        # records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
        records = []
        if is_tls_v2:
            length = client_hello_ssl_v2(stream)
            print("SSv2 tls found. extra len:{}".format(length))
            records, bytes_used = tls_multi_factory_new(stream[length:])
        else:
            records, bytes_used = tls_multi_factory_new(stream)
    except dpkt.ssl.SSL3Exception as exception:
        verboseprint('exception while parsing TLS records: {0}'.
                     format(exception))
        return
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    global encrypted_streams
    # if bytes_used != len(stream):
    #     add_to_buffer(ip, stream[bytes_used:])
    if len(records) > 1:
        print("SSL stream has many({}) records!".format(len(records)))
    for record in records:
        # record_type = pretty_name('tls_record', record.type)
        # print('captured TLS record type {0}'.format(record_type))
        # if record_type == 'handshake':
        if record.type == 0x16:  # HandShake
            parse_tls_handshake(ip, record.data, record.length, need_certs)
        if record.type == 0x15:  # Alert
            # if record_type == 'alert':
            parse_alert_message(connection, record.data)
        # The change cipher spec protocol is used to change the encryption being used by the client and server. It is normally used as part of the handshake process to switch to symmetric key encryption. The CCS protocol is a single message that tells the peer that the sender wants to change to a new set of keys, which are then created from information exchanged by the handshake protocol.
        # SSL修改密文协议的设计目的是为了保障SSL传输过程的安全性，因为SSL协议要求客户端或服务器端每隔一段时间必须改变其加解密参数。当某一方要改变其加解密参数时，就发送一个简单的消息通知对方下一个要传送的数据将采用新的加解密参数，也就是要求对方改变原来的安全参数。
        # if record_type == 'change_cipher': #  Since the Change Cipher Spec message modifies encryption settings, a new record should begin immediately afterwards, so that the new settings are immediately applied (in particular, it is crucial for security that the Finished message uses the new encryption and MAC).
        if record.type == 0x14:  # Change Cipher Spec
            print('[+] Change cipher - encrypted messages from now on for {0}'.format(connection))
            encrypted_streams.append(connection)
        if record.type == 0x17:
            # application data
            pass
        sys.stdout.flush()


def parse_tls_handshake(ip, data, record_length, need_certs=False):
    """
    Parses TLS Handshake message contained in data according to their type.
    """
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)

    global encrypted_streams
    if connection in encrypted_streams:
        print("*** MUST have cipher change flow first!!! ***")
        print('[+] Encrypted handshake message between {0}'.format(connection))
        return
    else:
        handshake_type = ord(data[:1])
        verboseprint('First 10 bytes {0}'.
                     format(hexlify(data[:10])))
        if handshake_type == 4:
            print('[#] New Session Ticket is not implemented yet')
            return

        total_len_consumed = 0
        while total_len_consumed < record_length:
            if total_len_consumed > 0:
                print("What the fuck is it???? OK, I need parse more data. Sorry....")
            buffers = data[total_len_consumed:]
            try:
                handshake = dpkt.ssl.TLSHandshake(buffers)
            except dpkt.ssl.SSL3Exception as exception:
                verboseprint('exception while parsing TLS handshake record: {0}'.
                             format(exception))
            except dpkt.dpkt.NeedData as exception:
                verboseprint('exception while parsing TLS handshake record: {0}'.
                             format(exception))
            try:
                ch = handshake.data
                # print("SSL version:", ch.version)
            except UnboundLocalError as exception:
                verboseprint('exception while parsing TLS handshake record: {0}'.
                             format(exception))
                break
            total_len_consumed += handshake.length + 4

            # ******** client is source IP, server is destination IP *******
            client = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
            server = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)

            if handshake.type == 0:
                # ssl_servers_with_handshake.add(server)
                print('<-  Hello Request {0} <- {1}'.format(client, server))
            elif handshake.type == 1:
                ssl_servers_with_client_hello.add(server)
                global client_hello_set
                global buffer
                connection = "{}-{}".format(client, server)

                """
                if connection == "192.168.56.114:1110-203.208.39.223:443":
                    print("192.168.56.114:1110-203.208.39.223:443 debug")
                """
                if connection in client_hello_set:
                    print("#" * 99)
                    print("Client Hello found again! {}, add into wanted data!".format(connection))
                    # add_to_complete_ssl_flow(connection, buffer)
                else:
                    client_hello_set.add(connection)
                print(' -> ClientHello {0} -> {1}'.format(client, server))
                # init buffer
                buffer[connection] = {"out": [], "in": []}
                # if connection == "185.9.34.103:58037-166.111.5.193:3390":
                #     print("check debug")
                #     print(buffer.keys())
                #     print(ssl_servers_with_client_hello)
                if need_more_parse:
                    parse_client_hello(handshake)
            elif handshake.type == 2:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerHello {1} <- {0}'.format(client, server))
                if need_more_parse:
                    parse_server_hello(handshake.data)
            elif handshake.type == 11:  # TLSCertificate
                # ssl_servers_with_handshake.add(client)
                print('<-  Certificate {1} <- {0}'.format(client, server))
                if need_certs:
                    hd_data = handshake.data
                    assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
                    certs = []
                    # print(dir(hd))
                    for i in range(len(hd_data.certificates)):
                        # print("hd.certificates[i]:", hd_data.certificates[i])
                        try:
                            cert = x509.Certificate.load(hd_data.certificates[i])
                            sha = cert.sha256_fingerprint.replace(" ", "")
                            # print(sha)
                            certs.append(sha)
                        except Exception as e:
                            print(traceback.format_exc())
                    connection_key = "{}-{}".format(server, client)
                    ssl_servers_certs[connection_key] = certs
                    print("*" * 66)
                    print("certs all here:", certs)
            elif handshake.type == 12:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerKeyExchange {1} <- {0}'.format(server, client))
            elif handshake.type == 13:
                # ssl_servers_with_handshake.add(client)
                print('<-  CertificateRequest {1} <- {0}'.format(client, server))
            elif handshake.type == 14:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerHelloDone {1} <- {0}'.format(client, server))
            elif handshake.type == 15:
                # ssl_servers_with_handshake.add(server)
                print(' -> CertificateVerify {0} -> {1}'.format(client, server))
            elif handshake.type == 16:
                # ssl_servers_with_handshake.add(server)
                print(' -> ClientKeyExchange {0} -> {1}'.format(client, server))
            elif handshake.type == 20:
                # ssl_servers_with_handshake.add(server)
                print(' -> Finished {0} -> {1}'.format(client, server))


def get_tls_certs(stream):
    if not stream:
        return []
    is_tls_v2, version3 = check_tls_version(stream)
    if not (is_tls_v2 or version3):
        print("NOT a ssl flow!!!")
        return []

    if (stream[0]) not in {20, 21, 22, 23}:
        print("Data weird!!! check again!!! TODO!!!", list(stream[:30]))
        return []
    # print("Found reassembled segments data: {}".format(stream[0]))
    # print("SSL tcp payload:", list(stream))
    try:
        # records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
        records = []
        if is_tls_v2:
            length = client_hello_ssl_v2(stream)
            print("SSv2 tls found. extra len:{}".format(length))
            records, bytes_used = tls_multi_factory_new(stream[length:])
        else:
            records, bytes_used = tls_multi_factory_new(stream)
    except dpkt.ssl.SSL3Exception as exception:
        verboseprint('exception while parsing TLS records: {0}'.
                     format(exception))
        return []
    if len(records) > 1:
        print("SSL stream has many({}) records!".format(len(records)))
    ans = []
    for record in records:
        # record_type = pretty_name('tls_record', record.type)
        # print('captured TLS record type {0}'.format(record_type))
        # if record_type == 'handshake':
        if record.type == 0x16:  # HandShake
            certs = parse_tls_certs(record.data, record.length)
            ans += certs
        if record.type == 0x17:
            # application data
            pass
        sys.stdout.flush()
    return ans


def parse_tls_certs(data, record_length):
    """
    Parses TLS Handshake message contained in data according to their type.
    """
    ans = []
    handshake_type = ord(data[:1])
    if handshake_type == 4:
        print('[#] New Session Ticket is not implemented yet')
        return ans

    total_len_consumed = 0
    while total_len_consumed < record_length:
        if total_len_consumed > 0:
            print("What the fuck is it???? OK, I need parse more data. Sorry....")
        buffers = data[total_len_consumed:]
        try:
            handshake = dpkt.ssl.TLSHandshake(buffers)
        except dpkt.ssl.SSL3Exception as exception:
            verboseprint('exception while parsing TLS handshake record: {0}'.
                         format(exception))
            break
        except dpkt.dpkt.NeedData as exception:
            verboseprint('exception while parsing TLS handshake record: {0}'.
                         format(exception))
            break
        try:
            ch = handshake.data
        except UnboundLocalError as exception:
            verboseprint('exception while parsing TLS handshake record: {0}'.
                         format(exception))
            break
        total_len_consumed += handshake.length + 4
        if handshake.type == 11:  # TLSCertificate
            # ssl_servers_with_handshake.add(client)
            hd_data = handshake.data
            assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
            certs = []
            # print(dir(hd))
            for i in range(len(hd_data.certificates)):
                try:
                    # print("hd.certificates[i]:", hd_data.certificates[i])
                    cert = x509.Certificate.load(hd_data.certificates[i])
                    sha = cert.sha256_fingerprint.replace(" ", "")
                    # print(sha)
                    certs.append(sha)
                except Exception as e:
                    print(traceback.format_exc())
            ans += certs
    return ans


def unpacker(type_string, packet):
    """
    Returns network-order parsed data and the packet minus the parsed data.
    """
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        # data = ''.join(data)
        data = data
    return data, packet[length:]


def parse_server_hello(handshake):
    """
    Parses server hello handshake.
    """
    payload = handshake.data
    session_id, payload = unpacker('p', payload)
    cipher_suite, payload = unpacker('H', payload)
    print('[*]   Cipher: {0}'.format(pretty_name('cipher_suites',
                                                 cipher_suite)))
    compression, payload = unpacker('B', payload)
    print('[*]   Compression: {0}'.format(pretty_name('compression_methods',
                                                      compression)))
    extensions = parse_extensions(payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_client_hello(handshake):
    hello = handshake.data
    compressions = []
    cipher_suites = []
    extensions = []
    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suites, pretty_cipher_suites = parse_extension(payload, 'cipher_suites')
    verboseprint('TLS Record Layer Length: {0}'.format(len(handshake)))
    verboseprint('Client Hello Version: {0}'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    verboseprint('Client Hello Length: {0}'.format(len(hello)))
    verboseprint('Session ID: {0}'.format(hexlify(session_id)))
    print('[*]   Ciphers: {0}'.format(pretty_cipher_suites))
    # consume 2 bytes for each cipher suite plus 2 length bytes
    payload = payload[(len(cipher_suites) * 2) + 2:]
    compressions, pretty_compressions = parse_extension(payload, 'compression_methods')
    print('[*]   Compression methods: {0}'.format(pretty_compressions))
    # consume 1 byte for each compression method plus 1 length byte
    payload = payload[len(compressions) + 1:]
    extensions = parse_extensions(payload)
    for extension in extensions:
        print('      {0}'.format(extension))


def parse_extensions(payload):
    """
    Parse data as one or more TLS extensions.
    """
    extensions = []
    # print("payload:", payload)
    if len(payload) <= 0:
        return []
    print('[*]   Extensions:')
    extensions_len, payload = unpacker('H', payload)
    verboseprint('Extensions Length: {0}'.format(extensions_len))
    while len(payload) > 0:
        extension = Extension(payload)
        extensions.append(extension)
        # consume 2 bytes for type and 2 bytes for length
        payload = payload[extension._length + 4:]
    return extensions


def parse_alert_message(connection, payload):
    """
    Parses a TLS alert message.
    """
    global encrypted_streams
    verboseprint(hexlify(payload))
    if connection in encrypted_streams:
        print('[+] Encrypted TLS Alert message between {0}'.format(connection))
        # presume the alert message ended the encryption
        encrypted_streams.remove(connection)
    else:
        alert_level, payload = unpacker('B', payload)
        alert_description, payload = unpacker('B', payload)
        print('[+] TLS Alert message between {0}: {1} {2}'.
              format(connection, pretty_name('alert_level', alert_level),
                     pretty_name('alert_description', alert_description)))


def parse_extension(payload, type_name):
    """
    Parses an extension based on the type_name.
    Returns an array of raw values as well as an array of prettified values.
    """
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    format_entry = 'B'
    list_length = 0
    if type_name == 'elliptic_curves':
        format_list_length = 'H'
        format_entry = 'H'
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'heartbeat':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'next_protocol_negotiation':
        format_entry = 'p'
    else:
        if len(payload) > 1:  # contents are a list
            list_length, payload = unpacker(format_list_length, payload)
    verboseprint('type {0}, list type is {1}, number of entries is {2}'.
                 format(type_name, format_list_length, list_length))
    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if list_length:
        payload = payload[:list_length]
    while (len(payload) > 0):
        if type_name == 'server_name':
            _type, payload = unpacker('B', payload)
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
        entries.append(entry)
        if type_name == 'signature_algorithms':
            pretty_entries.append('{0}-{1}'.
                                  format(pretty_name
                                         ('signature_algorithms_hash',
                                          entry >> 8),
                                         pretty_name('signature_algorithms_signature',
                                                     entry % 256)))
        else:
            if format_entry.lower() == 'p':
                pretty_entries.append(entry)
            else:
                pretty_entries.append(pretty_name(type_name, entry))
    return entries, pretty_entries


def pretty_name(name_type, name_value):
    """Returns the pretty name for type name_type."""
    if name_type in PRETTY_NAMES:
        if name_value in PRETTY_NAMES[name_type]:
            name_value = PRETTY_NAMES[name_type][name_value]
        else:
            name_value = '{0}: unknown value {1}'.format(name_value, name_type)
    else:
        name_value = 'unknown type: {0}'.format(name_type)
    return name_value



def remove_over_time_flows(flows):
    ans = []
    if flows:
        ans = [flows[0]]
        flow_start_time = flows[0][2]
        i = 1
        ten_minutes = 10 * 60
        while i < len(flows) and (flows[i][2] - flow_start_time) <= ten_minutes:
            ans.append(flows[i])
            i += 1
        if i != len(flows):
            print("!!!CAUTION: found flow exceed ten minutes!!!start:", flows[0] ,)
            print("!!!CAUTION: found flow exceed ten minutes!!!end:", flows[i])
    return ans


def read_file(filename):
    try:
        certs_filter = CertFilter()
        dir_name = os.path.dirname(filename).split("/")[-1]
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            i = 1
            for timestamp, packet in capture:
                analyze_packet(timestamp, packet, i, OP.CHECK_TLS_PACKET)
                print(i, timestamp, "packet processing")
                i += 1

            print("found {} different flows total!!!".format(len(buffer)))
            print("server_ip_set: {}".format(server_ip_set))
            print("*" * 99)
            print("all tcp flow are here!!!")
            print("*" * 99)
            wanted_ssl_flow = []
            for connection_key, flows in buffer.items():
                for raw_flow in flows:
                    # print(raw_flow)
                    flow = {"connection": connection_key, "payload": {"in": raw_flow["in"], "out": raw_flow["out"]}}
                    in_payload = bytearray() # bytes is immutable. Use bytearray.
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! out data has no certs !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
                    flow["payload"]["out"] = remove_over_time_flows(flow["payload"]["out"])
                    flow["payload"]["in"] = remove_over_time_flows(flow["payload"]["in"])
                    for tag, nth, timestamp, payload in flow["payload"]["in"]:
                        in_payload.extend(payload)
                    print("connection:", flow["connection"])
                    certs = get_tls_certs(bytes(in_payload))
                    flow["certs"] = certs

                    if certs:
                        print("*" * 99)
                        if not has_application_data(flow["payload"]["in"]) and not has_application_data \
                                (flow["payload"]["out"]):
                            print("NO app data!!!")
                            continue
                        if not is_white_sample:
                            server_ip = flow["connection"].split("-")[1].split(":")[0]
                            if certs_filter.is_white_flow(server_ip, certs):
                                print("found white flow in black sample!!!")
                                continue
                        # change to bytes list
                        flow["payload"]["out"] = [(tag, nth, timestamp, list(payload)) for
                                                  tag, nth, timestamp, payload in flow["payload"]["out"]]
                        flow["payload"]["in"] = [(tag, nth, timestamp, list(payload)) for
                                                 tag, nth, timestamp, payload in flow["payload"]["in"]]

                        print("CHECK DATA:")
                        print("-" * 99)
                        print("payload out:", [(tag, nth, timestamp, (payload[:10])) for tag, nth, timestamp, payload in
                                               flow["payload"]["out"]])
                        print("len:", len([(tag, nth, timestamp, (payload[:10])) for tag, nth, timestamp, payload in
                                           flow["payload"]["in"]]))
                        print("payload in:", [(tag, nth, timestamp, (payload[:10])) for tag, nth, timestamp, payload in
                                              flow["payload"]["in"]])
                        print("certs:", flow["certs"])
                        wanted_ssl_flow.append(flow)
                        print("-" * 99)

            global output_file
            if wanted_ssl_flow:
                if dir_name:
                    filename, ext = os.path.splitext(output_file)
                    output_file_name = "{}-{}{}".format(filename, dir_name, ext)
                else:
                    output_file_name = output_file
                with open(output_file_name, "wb") as f:
                    # json.dump(wanted_ssl_flow, f)
                    pickle.dump(wanted_ssl_flow, f)
            print("total flow:", len(wanted_ssl_flow))

    except Exception as e:
        print('could not parse {}, error:{}'.format(filename, e))
        traceback.print_exc()


def main():
    """
    Main program loop.
    """
    global cap_filter
    global interface
    parse_arguments()
    if filename:
        read_file(filename)


if __name__ == "__main__":
    main()
