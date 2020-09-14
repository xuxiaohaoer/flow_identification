#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
import argparse
from binascii import hexlify
import socket
import struct
import json
import sys
import textwrap
import dpkt
from constants import PRETTY_NAMES
from asn1crypto import x509
import os
global streambuffer
streambuffer = {}
global encrypted_streams
encrypted_streams = []  # change_cipher
global ssl_servers_certs
ssl_servers_certs = {}
global ssl_servers_with_client_hello
ssl_servers_with_client_hello = set()
global client_hello_set
client_hello_set = set()
global ssl_flows
ssl_flows = []
global buffer
buffer = {}
need_more_parse = True


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


def analyze_packet(_timestamp, packet, nth):
    """
    Main analysis loop for pcap.
    """
    eth = dpkt.ethernet.Ethernet(packet)
    if isinstance(eth.data, dpkt.ip.IP):
        # print("timestamp:", _timestamp, "debug")
        parse_ip_packet(eth.data, nth, _timestamp)


def parse_arguments():
    """
    Parses command line arguments.
    """
    global filename
    global verboseprint
    global output_file
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
    filename = None
    if args.read:
        filename = args.read
    output_file = "demo_output.txt"
    if args.output:
        output_file = args.output


def parse_ip_packet(ip, nth, timestamp):
    """
    Parses IP packet.
    """
    sys.stdout.flush()
    if isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data):
        # print("****TCP packet found****", "tcp payload:", list(ip.data.data))
        parse_tcp_packet(ip, nth, timestamp)


def parse_tcp_packet(ip, nth, timestamp):
    """
    Parses TCP packet.
    """
    stream = ip.data.data
    """ refer: The Transport Layer Security (TLS) Protocol URL:https://tools.ietf.org/html/rfc5246
    enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23), (255)
      } ContentType;
    """
    # ssl flow
    if (stream[0]) in {20, 21, 22, 23}:
        if (stream[0]) in {20, 21, 22}:
            parse_tls_records(ip, stream, nth)
        else:
            connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                                  ip.data.sport,
                                                  socket.inet_ntoa(ip.dst),
                                                  ip.data.dport)
            print("*" * 99)
            print("23 SSL application data:{} 10 sample:{} nth:{}".format(connection, list(stream[:10]), nth))
        # buffer record recent ssl flow from handshake to app data  TODO precise description
        record_recent_data_flow(ip, stream, nth, timestamp)


def has_application_data(flow_list):
    for flow in flow_list:
        if flow[0] == 23:
            return True
    return False


def record_recent_data_flow(ip, stream, nth, timestamp):
    global buffer
    src_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
    dst_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)
    flow_dir = FlowDirection.UNKNOWN
    connection_key = ""
    # identify flow direction
    if dst_ip in ssl_servers_with_client_hello:  # OUT flow
        flow_dir = FlowDirection.OUT
        connection_key = "{}-{}".format(src_ip, dst_ip)
    elif src_ip in ssl_servers_with_client_hello:  # IN flow
        flow_dir = FlowDirection.IN
        connection_key = "{}-{}".format(dst_ip, src_ip)
    else:
        print("Warning: not find in ssl_servers_with_client_hello! src_ip:{} dst_ip:{}".format(src_ip, dst_ip))
        print("dump this NOT useful data!!! 10:", list(stream[:10]), "nth:", nth)
        return

    if connection_key in buffer:  # buffer has only data with client hello
        if flow_dir == FlowDirection.OUT:
            buffer[connection_key]["out"].append((stream[0], nth, timestamp, list(stream)))
        elif flow_dir == FlowDirection.IN:
            buffer[connection_key]["in"].append((stream[0], nth, timestamp, list(stream)))
    else:
        print("Warning: not find client hello. src_ip:{} dst_ip:{} {}".format(src_ip, dst_ip, connection_key))
        print("dump this NOT useful data!!! 10:", list(stream[:10]), "nth:", nth)
        if src_ip == "166.111.5.193:3390":
            print("check debug")
            print(ssl_servers_with_client_hello)
            print(src_ip in ssl_servers_with_client_hello)
            print(dst_ip in ssl_servers_with_client_hello)


def add_to_complete_ssl_flow(connection_key, buffer):
    # We want SSL flow data from ***ClientHello*** to ***AppData***
    global ssl_flows
    assert connection_key in client_hello_set
    server = connection_key.split("-")[1]
    assert server in ssl_servers_with_client_hello
    print("**** add to wanted flow *** {}".format(connection_key))
    ssl_flows.append({"connection": connection_key, "payload": dict(buffer[connection_key]),
                      "certs": list(ssl_servers_certs[connection_key]) if connection_key in ssl_servers_certs else []})


def add_to_buffer(ip, partial_stream):
    """
    Adds partial_stream of ip to global stream buffer.
    """
    global streambuffer
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    streambuffer[connection] = partial_stream
    verboseprint('Added {0} bytes (seq {1}) to streambuffer for {2}'.
                 format(len(partial_stream), ip.data.seq, connection))


def parse_tls_records(ip, stream, nth):
    """
    Parses TLS Records.
    """
    print("*" * 99)
    print("20 21 22 SSL tcp payload(10):", list(stream[:10]), "nth:", nth)
    # print("SSL tcp payload:", list(stream))
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        verboseprint('exception while parsing TLS records: {0}'.
                     format(exception))
        return
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
                                          ip.data.sport,
                                          socket.inet_ntoa(ip.dst),
                                          ip.data.dport)
    global encrypted_streams
    if bytes_used != len(stream):
        add_to_buffer(ip, stream[bytes_used:])
    if len(records) > 1:
        print("SSL stream has many({}) records!".format(len(records)))
    for record in records:
        record_type = pretty_name('tls_record', record.type)
        print('captured TLS record type {0}'.format(record_type))
        if record_type == 'handshake':
            parse_tls_handshake(ip, record.data, record.length)
        if record_type == 'alert':
            parse_alert_message(connection, record.data)
        # The change cipher spec protocol is used to change the encryption being used by the client and server. It is normally used as part of the handshake process to switch to symmetric key encryption. The CCS protocol is a single message that tells the peer that the sender wants to change to a new set of keys, which are then created from information exchanged by the handshake protocol.
        # SSL修改密文协议的设计目的是为了保障SSL传输过程的安全性，因为SSL协议要求客户端或服务器端每隔一段时间必须改变其加解密参数。当某一方要改变其加解密参数时，就发送一个简单的消息通知对方下一个要传送的数据将采用新的加解密参数，也就是要求对方改变原来的安全参数。
        if record_type == 'change_cipher':  # Since the Change Cipher Spec message modifies encryption settings, a new record should begin immediately afterwards, so that the new settings are immediately applied (in particular, it is crucial for security that the Finished message uses the new encryption and MAC).
            print('[+] Change cipher - encrypted messages from now on for {0}'.format(connection))
            encrypted_streams.append(connection)
        sys.stdout.flush()


def parse_tls_handshake(ip, data, record_length):
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
            if handshake.type == 1:
                ssl_servers_with_client_hello.add(server)
                global client_hello_set
                global buffer
                connection = "{}-{}".format(client, server)
                if connection in client_hello_set:
                    print("#" * 99)
                    print(
                        "Client Hello found again! {}, I will check if there is application flow data and add into wanted data!".format(
                            connection))
                    if has_application_data(buffer[connection]["out"]) or has_application_data(
                            buffer[connection]["in"]):  # has already trans data before and a new flow come
                        # record previous SSL data flow
                        add_to_complete_ssl_flow(connection, buffer)
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
            if handshake.type == 2:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerHello {1} <- {0}'.format(client, server))
                if need_more_parse:
                    parse_server_hello(handshake.data)
            if handshake.type == 11:  # TLSCertificate
                # ssl_servers_with_handshake.add(client)
                print('<-  Certificate {1} <- {0}'.format(client, server))
                hd_data = handshake.data
                assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
                certs = []
                # print(dir(hd))
                for i in range(len(hd_data.certificates)):
                    print("hd.certificates[i]:", hd_data.certificates[i])
                    cert = x509.Certificate.load(hd_data.certificates[i])
                    sha = cert.sha256_fingerprint.replace(" ", "")
                    print(sha)
                    certs.append(sha)
                connection_key = "{}-{}".format(server, client)
                ssl_servers_certs[connection_key] = certs
                print("*" * 66)
                print("certs all here:", certs)
            if handshake.type == 12:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerKeyExchange {1} <- {0}'.format(server, client))
            if handshake.type == 13:
                # ssl_servers_with_handshake.add(client)
                print('<-  CertificateRequest {1} <- {0}'.format(client, server))
            if handshake.type == 14:
                # ssl_servers_with_handshake.add(client)
                print('<-  ServerHelloDone {1} <- {0}'.format(client, server))
            if handshake.type == 15:
                # ssl_servers_with_handshake.add(server)
                print(' -> CertificateVerify {0} -> {1}'.format(client, server))
            if handshake.type == 16:
                # ssl_servers_with_handshake.add(server)
                print(' -> ClientKeyExchange {0} -> {1}'.format(client, server))
            if handshake.type == 20:
                # ssl_servers_with_handshake.add(server)
                print(' -> Finished {0} -> {1}'.format(client, server))
            # if "185.9.34.103:58037" in ssl_servers_with_handshake:
            #     print("ABCD!!!FUCK!!!")


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


def main():
    """
    Main program loop.
    """
    global cap_filter
    global interface
    parse_arguments()
    i = 0
    base_dir = "data/eta_1/train/black/"
    for filename in os.listdir(base_dir):
        if i == 1:
            break
        filename = "192.168.57.167.pcap"
        print(filename)
        read_file(base_dir + filename)
        i += 1


def process_left_buffer():
    print("********process_left_buffer********")
    global buffer
    for connection_key in buffer:
        if has_application_data(buffer[connection_key]["out"]) or has_application_data(buffer[connection_key]["in"]):
            # record previous SSL data flow
            add_to_complete_ssl_flow(connection_key, buffer)
        else:
            print("Bad flow found, has no data but ssl handshake!", buffer[connection_key])


def read_file(filename):
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            i = 1
            tem = 0
            for timestamp, packet in capture:
                if i == 1:
                    tem = timestamp
                analyze_packet(timestamp - tem, packet, i)
                print(i, timestamp - tem)
                i += 1
            process_left_buffer()
            print("*" * 99)
            print("ssl flow wanted here!!!")
            print("*" * 99)

            global output_file
            data = [flow for flow in ssl_flows if flow["certs"]]
            if data:
                with open(output_file, "w") as f:
                    json.dump(data, f)

            cnt = 0
            for flow in ssl_flows:
                if flow["certs"]:
                    cnt += 1
                    print("connection:", flow["connection"])
                    print("payload out:", [(tag, nth, timestamp, payload[:10]) for tag, nth, timestamp, payload in
                                           flow["payload"]["out"]])
                    print("payload in:", [(tag, nth, timestamp, payload[:10]) for tag, nth, timestamp, payload in
                                          flow["payload"]["in"]])
                    print("certs:", flow["certs"])
                    print("*" * 99)
            print("total flow:", cnt)
            f.close()
    except IOError:
        print('could not parse {0}'.format(filename))


if __name__ == "__main__":
    main()