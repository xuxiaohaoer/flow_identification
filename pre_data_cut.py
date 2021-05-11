# from __future__ import absolute_import
# from __future__ import print_function
import os
import socket
import sys
from constants import PRETTY_NAMES
import numpy as np
# from asn1crypto import x509

# from dateutil import parser
from datetime import datetime
import OpenSSL
import csv
from cal import *

import dpkt
from flowFeature import featureType

import math
from tqdm import tqdm
need_more_parse = True  # 需要更多TLS信息
need_more_certificate = True
need_http = True
"""
    切隔负载
"""

class flowRecord:
    def __init__(self, num, flow_size, flow_starttime, flow_endtime):
        self.num = num
        self.flow_size = flow_size
        self.flow_duration = 0
        self.flow_starttime = flow_starttime
        self.flow_endtime = flow_endtime


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


def analyze_packet(timestamp, packet, nth):
    """
    Main analysis loop for pcap.
    """

    eth = dpkt.ethernet.Ethernet(packet)
    feature.tls_seq.append(0)
    if isinstance(eth.data, dpkt.ip.IP):
        parse_ip_packet(eth, nth, timestamp)
        # parse_ip_data(packet, nth, timestamp)

def parse_ip_data(packet, nth, timestamp):
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data
    tcp = ip.data
    data = tcp.data

    if (len(data)!=0):
        if len(feature.content)<3:
            # print(packet[14:].hex())
            feature.content.append(packet[14:])
            feature.content_payload.append(len(eth))



def parse_ip_packet(eth, nth, timestamp):
    """
    Parses IP packet.
    """

    ip = eth.data


    tcp_data = ip.data
    sys.stdout.flush()
    size = len(eth)  # 包大小
    feature.packetsize_packet_sequence.append(size)
    payload = len(ip.data.data)  # 有效负载大小
    feature.payload_seq.append(payload)
    rest_load = None
    if isinstance(ip.data, dpkt.tcp.TCP):
        if (len(ip.data.data)!=0):
            parse_tcp_packet(ip, nth, timestamp)
    # 提取 ip地址、端口号
    if nth == 1:
        feature.ip_src = socket.inet_ntoa(ip.src)
        feature.ip_dst = socket.inet_ntoa(ip.dst)
        feature.sport = int(ip.data.sport)
        feature.dport = int(ip.data.dport)
    if socket.inet_ntoa(ip.src) == feature.ip_src:
        feature.time_src_sequence.append(timestamp)
        feature.packetsize_src_sequence.append(size)
        feature.num_src += 1
        feature.size_src += size
        feature.dir_seq.append(1)
    else:
        feature.time_dst_sequence.append(timestamp)
        feature.packetsize_dst_sequence.append(size)
        feature.num_dst += 1
        feature.size_dst += size
        feature.dir_seq.append(-1)

    flag = socket.inet_ntoa(ip.src) + ' ' + socket.inet_ntoa(ip.dst) + ' ' + str(ip.data.dport) + ' ' + str(
        ip.data.sport)
    flag_1 = socket.inet_ntoa(ip.dst) + ' ' + socket.inet_ntoa(ip.src) + ' ' + str(ip.data.sport) + ' ' + str(
        ip.data.dport)
    if contact.__contains__(flag):
        contact[flag].num += 1
        contact[flag].flow_endtime = timestamp
        contact[flag].flow_size += size
    # elif contact.__contains__(flag_1):
    #     contact[flag_1].num += 1
    #     contact[flag_1].flow_endtime = timestamp
    #     contact[flag_1].flow_size += size
    else:
        tem = flowRecord(0, size, timestamp, timestamp)
        contact[flag] = tem

    feature.packetsize_size += size

    if isinstance(ip.data, dpkt.tcp.TCP) and payload:
        if socket.inet_ntoa(ip.src) == feature.ip_dst:
            direction = 1
        else:
            direction = -1
        dirpath = direction * payload
        if len(feature.sequence) < 20:
            feature.sequence.append(dirpath)

    if need_more_certificate:
        class FlowFlag:
            def __init__(self, seq, data):
                self.seq = seq

                self.seq_exp = seq + len(data)
                self.data = data
                self.sequence = []
                self.nth_seq = []
                self.ip = dpkt.ip.IP()
                self.timestamp = 0

        # 设置flow记录流的各条记录，以解决tcp resseambeld segment
        flow_flag = socket.inet_ntoa(ip.src) + '->' + socket.inet_ntoa(ip.dst)
        flow_flag1 = socket.inet_ntoa(ip.dst) + '->' + socket.inet_ntoa(ip.src)
        # 存在udp 没有seq和ack
        try:
            seq = ip.data.seq
            ack = ip.data.ack
        except AttributeError as exception:
            seq = 0
            ack = 0
        data = ip.data.data
        data_flag = data
        try:
            if data[0] in {20, 21, 22, 23}:
                # 直接可以解压一部分，且返回剩余负载部分
                data_tem, flag = parse_tls_records(ip, data, nth, [nth], timestamp)
                if flag:
                    if len(data_tem) == 0:
                        data_tem = bytes(0)
                    data = data_tem
        except:
            pass

        # 接收到反向的包
        if flow_flag1 in flow.keys():
            if ack >= flow[flow_flag1].seq:
                if len(flow[flow_flag1].data) != 0:
                    tem = flow[flow_flag1].data
                    nth_flag = flow[flow_flag1].nth_seq
                    ip_tem = flow[flow_flag1].ip
                    timestamp_tem = flow[flow_flag1].timestamp
                    if tem[0] in {20, 21, 22, 23}:
                        rest_load, flag = parse_tls_records(ip_tem, tem, nth_flag[-1], nth_flag, timestamp_tem)

                try:
                    if rest_load != None and not len(data_flag):
                        if rest_load == bytes(0):
                            flow[flow_flag1].sequence.clear()
                            flow[flow_flag1].nth_seq.clear()
                            flow[flow_flag1].ip = dpkt.ip.IP()
                            flow[flow_flag1].timestamp = 0
                        if rest_load[0] in {20, 21, 22, 23}:
                            flow[flow_flag1].data = rest_load
                            # 中间插入一条ack较大值
                            flow[flow_flag1].sequence = [rest_load]
                            flow[flow_flag1].ip = ip
                            flow[flow_flag1].timestamp = timestamp
                    else:
                        flow.pop(flow_flag1)
                        # flow[flow_flag1].data = bytes(0)
                        # flow[flow_flag1].sequence.clear()
                        # flow[flow_flag1].nth_seq.clear()
                except:
                    flow.pop(flow_flag1)
                    # flow[flow_flag1].data = bytes(0)
                    # flow[flow_flag1].sequence.clear()
                    # flow[flow_flag1].nth_seq.clear()

        # if data == None:
        #     print(nth)

        if len(data):
            if flow_flag not in flow.keys():
                if data != bytes(0):
                    if data[0] in {20, 21, 22, 23}:
                        flow[flow_flag] = FlowFlag(seq, data)
                        flow[flow_flag].sequence.append(data)
                        flow[flow_flag].nth_seq.append(nth)
                        flow[flow_flag].seq_exp = seq + len(data_flag)
                        flow[flow_flag].ip = ip
                        flow[flow_flag].timestamp = timestamp
            else:
                # if flow[flow_flag].seq < seq:
                if flow[flow_flag].seq_exp == seq:
                    # print(nth, "###")
                    flow[flow_flag].seq = seq
                    flow[flow_flag].seq_exp += len(data_flag)
                    if data not in flow[flow_flag].sequence:
                        if data not in flow[flow_flag].data:
                            flow[flow_flag].data += data
                            flow[flow_flag].sequence.append(data)
                            flow[flow_flag].nth_seq.append(nth)
                            flow[flow_flag].ip = ip
                            flow[flow_flag].timestamp = timestamp
                else:
                    pass


def parse_tcp_packet(ip, nth, timestamp):
    """
    Parses TCP packet.
    """
    rest_load = None
    tcp_data = ip.data
    stream = ip.data.data

    # ssl flow
    #  提取标志位

    # if cal_psh(tcp_data.flags):
    #     feature.psh += 1
    # if cal_urg(tcp_data.data.flags):
    #     feature.urg += 1

    if (stream[0]) in {20, 21, 22, 23, 128, 25}:
        if (stream[0]) in {20, 21, 22}:
            # print("---")
            pass
            # rest_load = parse_tls_records(ip, stream, nth)
        if (stream[0]) == 128:  # sslv2 client hello

            # feature.flag = True
            try:
                cipher_length = stream[6] + stream[5] * 256
            except:
                cipher_length = 0
            if len(stream) > 6:
                if stream[2] == 1:  # sslv2 client hello

                    head = bytes(0)
                    head += nth.to_bytes(length=2, byteorder='big', signed=False)

                    # head += math.floor(timestamp * 1000).to_bytes(length=4, byteorder='big', signed=False)


                    head += (len(ip) + 14).to_bytes(length=2, byteorder='big', signed=False)
                    head += ip.src
                    head += ip.dst
                    head += ip.data.sport.to_bytes(length=2, byteorder='big', signed=False)
                    head += ip.data.dport.to_bytes(length=2, byteorder='big', signed=False)
                    if (feature.client_hello_content == bytes(0)):
                        feature.client_hello_content = head + stream[2:]


                    # length = stream[1]
                    # dataClientHello = stream[:length+2]

                    feature.tls_seq[nth - 1] = stream[2]
                    feature.cipher_num = max(cipher_length, feature.cipher_num)
                    tem = stream[6] * 256 + stream[7] + 11  # 加密组件开始的stream的index
                    i = 0
                    while i < cipher_length:
                        cipher = 0
                        if tem + i + 2 < len(stream):
                            cipher = stream[tem + i + 2] + stream[tem + i + 1] * 256 + stream[tem + i] * 256 * 256
                        if cipher not in feature.cipher_support:
                            feature.cipher_support.append(cipher)
                        i += 3
                # print(nth, stream[6])
        # if (stream[0]) == 25:
        #     rest_load = parse_tls_records(ip, stream, nth)
    return rest_load


def multiple_handshake(nth, buf):
    i, n = 0, len(buf)
    msgs = []
    while i + 5 <= n:
        tot = 0
        v = buf[i + 1:i + 3]
        if v in dpkt.ssl.SSL3_VERSION_BYTES:
            head = buf[i:i + 5]
            tot_len = int.from_bytes(buf[i + 3:i + 5], byteorder='big')
            j = i + 5
            while j <= tot_len + 1:
                try:
                    Record_len = int.from_bytes(buf[j + 1:j + 4], byteorder='big', signed=False)
                    len_tem_b = (Record_len + 4).to_bytes(length=2, byteorder='big', signed=False)
                    head_tem = head[0:3] + len_tem_b
                    tem = head_tem + buf[j:j + Record_len + 4]
                except:
                    # Record_len = 0
                    pass
                try:
                    msg = dpkt.ssl.TLSRecord(tem)
                    msgs.append(msg)
                    record_type = pretty_name('tls_record', msg.type)

                    if record_type == 'handshake':
                        handshake_type = ord(msg.data[:1])
                        if handshake_type == 11:  # certificate

                            tem = 0
                            a = []
                            a = parse_tls_certs(nth, msg.data, msg.length)
                            # return msgs, tot_len
                        elif handshake_type == 2:  # server hello
                            pass

                    # print(nth, "***{}***".format(msg))

                except dpkt.NeedData:
                    pass
                try:
                    j += Record_len + 4
                    i += j
                except:
                    pass
                # if Record_len != 0:
                #     j += Record_len + 4
                #     i += j
                # else:
                #     j += 4
                #     i += j
            # 防止无限循环
            if j == i + 5:
                i = n


        else:
            raise dpkt.ssl.SSL3Exception('Bad TLS version in buf: %r' % buf[i:i + 5])
        # i += tot
    return msgs, i


def parse_tls_records(ip, stream, nth, nth_seq, timestamp):
    """
    Parses TLS Records.
    return:
    flag: 是否分析成功
    """


    flag = False
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        return stream, False
    # mutliple


    if bytes_used == 0:
        try:
            records, bytes_used = multiple_handshake(nth, stream)
            flag = True

        except:
            return stream, False
        if bytes_used > len(stream):
            return stream, False

    # multiple 只解压了第一个报文
    try:

        if records[0].type == 22:
            handshake_type = records[0].data[0]
            # 握手格式要求，避免加入application data等信息
            if handshake_type in {1, 2, 11, 12, 14, 16, 21}:
                record_len = int.from_bytes(records[0].data[1:4], byteorder='big')
                if record_len + 4 < records[0].length:
                    flag = True
                    records, bytes_used = multiple_handshake(nth, stream)
    except:
        return stream, False
    flag = True

    n = 0
    type = []
    handshake_scope = [1, 2, 11, 12, 14, 16]
    for record in records:
        # print(nth, record.version)
        record_type = pretty_name('tls_record', record.type)

        if record_type == 'application_data':
            i = (len(stream) - bytes_used) // 1460
            # print(nth, nth_seq[-1-i],record_type)
            # 存在多余bytes_used，说明组合了多余的包，应该回退
            try:
                nth = nth_seq[-1 - i]
            except:
                print(len(records))
                print(len(stream), bytes_used)
                print(feature.ip_dst, feature.ip_src, nth, i)
            content = np.zeros(256)
            entropy = 0
            for key in record.data:
                content[key] += 1
            feature.cipher_bitFre += content

            if content.sum() != 0:
                content /= content.sum()
            for key in content:
                if key != 0:
                    entropy -= (key) * math.log(key, 2)
            feature.cipher_app_entropy.append(entropy)
            # if len(feature.cipher_app_content) < 1600:
            #     feature.cipher_app_content += record.data
            #     feature.cipher_app_content = feature.cipher_app_content[:1600]

            feature.cipher_app_num += 1

        if record_type == 'handshake':
            handshake_type = ord(record.data[:1])

            if handshake_type in handshake_scope:
                type.append(handshake_type)
            # print(nth, "handshake_type", handshake_type)
            if handshake_type == 2:  # server hello

                # buf_cont = record.type.to_bytes(length=1, byteorder='big', signed=False)
                # buf_ver = record.version.to_bytes(length=2, byteorder = 'big', signed=False)
                # buf_len = record.length.to_bytes(length = 2, byteorder= 'big', signed=False)
                # dataServerHello = buf_cont + buf_ver + buf_len + record.data

                feature.flow_num += 1
                feature.cipher = (record.data[-2] + record.data[-3] * 256)


                head = bytes(0)
                head += nth.to_bytes(length = 2, byteorder='big', signed=False)
                # head += math.floor(timestamp *1000).to_bytes(length =4, byteorder= 'big', signed= False)
                head += (len(ip) +14).to_bytes(length = 2, byteorder ='big', signed=False)
                head += ip.src
                head += ip.dst
                head += ip.data.sport.to_bytes(length=2, byteorder ='big', signed= False)
                head += ip.data.dport.to_bytes(length =2, byteorder = 'big', signed= False)

                if feature.server_hello_content == bytes(0):
                    feature.server_hello_content = head + record.data[:6] + record.data[38:]


            if handshake_type == 11:  # certificate

                # buf_cont = record.type.to_bytes(length=1, byteorder='big', signed=False)
                # buf_ver = record.version.to_bytes(length=2, byteorder='big', signed=False)
                # buf_len = record.length.to_bytes(length=2, byteorder='big', signed=False)
                # dataCertificate = buf_cont + buf_ver + buf_len + record.data
                # print("nth:", nth)
                # print(timestamp)
                # print(len(ip))
                # print((len(ip) + 14).to_bytes(length=2, byteorder='big', signed=False))
                # print(socket.inet_ntoa(ip.src))
                # print(socket.inet_ntoa(ip.dst))
                # print(ip.data.sport)
                # print(ip.data.dport)

                head = bytes(0)
                head += nth.to_bytes(length = 2, byteorder='big', signed=False)
                # head += math.floor(timestamp *1000).to_bytes(length =4, byteorder= 'big', signed= False)
                head += (len(ip) +14).to_bytes(length = 2, byteorder ='big', signed=False)
                head += ip.src
                head += ip.dst
                head += ip.data.sport.to_bytes(length=2, byteorder ='big', signed= False)
                head += ip.data.dport.to_bytes(length =2, byteorder = 'big', signed= False)
                len_cer = int.from_bytes(record.data[4:7], byteorder='big')  # 转换字节流为十进制
                data = record.data[7:]
                tem = 0
                a = []
                a = parse_tls_certs(nth, record.data, record.length)
                if feature.certificate_content == bytes(0):
                    feature.certificate_content = head + record.data

                while len(data):
                    len_cer_tem = int.from_bytes(data[0:3], byteorder='big')
                    certificate = data[3:len_cer_tem + 3]
                    data = data[len_cer_tem + 3:]
            if n == 0:
                if handshake_type == 1:  # sslv3 tlsv1 client hello
                    # feature.flag = True
                    try:
                        cipher_len = int(record.data[40 + record.data[38]])
                    except IndexError as exception:
                        cipher_len = 0
                        print(feature.name)

                    head = bytes(0)
                    head += nth.to_bytes(length=2, byteorder='big', signed=False)

                    # head += math.floor(timestamp * 1000).to_bytes(length=4, byteorder='big', signed=False)

                    # head += math.floor(timestamp * 1000).to_bytes(length=2, byteorder='big', signed=False)
                    head += (len(ip) + 14).to_bytes(length=2, byteorder='big', signed=False)
                    head += ip.src
                    head += ip.dst
                    head += ip.data.sport.to_bytes(length=2, byteorder='big', signed=False)
                    head += ip.data.dport.to_bytes(length=2, byteorder='big', signed=False)
                    if feature.client_hello_content == bytes(0):

                        feature.client_hello_content = head + record.data[:6] + record.data[38:]
                    # buf_cont = record.type.to_bytes(length=1, byteorder='big', signed=False)
                    # buf_ver = record.version.to_bytes(length=2, byteorder='big', signed=False)
                    # buf_len = record.length.to_bytes(length=2, byteorder='big', signed=False)
                    # dataClientHello= buf_cont + buf_ver + buf_len + record.data

                    feature.cipher_num = max(cipher_len, feature.cipher_num)
                    tem = 40 + record.data[38] + 1
                    i = 0
                    while i < cipher_len:
                        cipher = record.data[tem + i] * 256 + record.data[tem + i + 1]
                        if cipher not in feature.cipher_support:
                            feature.cipher_support.append(cipher)
                        i += 2
                    # print(nth, record.data[40])

        else:
            type.append(record.type)
        n += 1
        sys.stdout.flush()
    try:
        feature.tls_seq[nth - 1] = type
    except:
        print(nth, len(feature.tls_seq))
        print(feature.ip_src, feature.ip_dst)
    # ressembled tcp segments
    load = stream[bytes_used:]
    if load == None:
        load = bytes(0)
    return load, flag


def parse_tls_certs(nth, data, record_length):
    """
    Parses TLS Handshake message contained in data according to their type.
    """
    ans = []
    handshake_type = ord(data[:1])  # 握手类型
    if handshake_type == 4:
        print('[#] New Session Ticket is not implemented yet')
        return ans

    buffers = data[0:]
    try:
        handshake = dpkt.ssl.TLSHandshake(buffers)
    except dpkt.ssl.SSL3Exception as exception:
        pass
        # print('exception while parsing TLS handshake record: {0}'.format(exception))
    except dpkt.dpkt.NeedData as exception:
        pass
        # print('exception while parsing TLS handshake record: {0}'.format(exception))
    try:
        ch = handshake.data
    except UnboundLocalError as exception:
        pass
    else:
        if handshake.type == 11:  # TLS Certificate
            # ssl_servers_with_handshake.add(client)
            hd_data = handshake.data
            assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
            certs = []
            # print(dir(hd))
            if len(hd_data.certificates) != 0:
                cert_1 = hd_data.certificates[0]
                cert_1 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_1)
                if cert_1 not in feature.certificate:
                    feature.certificate.append(cert_1)
                    feature.cipher_subject.append(cert_1.get_subject().CN)
                    feature.cipher_issue.append(cert_1.get_issuer().CN)
                    # feature.cipher_certifcate_time.append(cert_1.get_notAfter()-cert_1.get_notBefore())
                    before = datetime.strptime(cert_1.get_notBefore().decode()[:-7], '%Y%m%d')
                    after = datetime.strptime(cert_1.get_notAfter().decode()[:-7], '%Y%m%d')
                    feature.cipher_certifcate_time.append((after - before).days)
                    feature.cipher_extension_count.append(cert_1.get_extension_count())
                    feature.cipher_sigature_alo.append(cert_1.get_signature_algorithm())
                    feature.cipher_version.append(cert_1.get_version())
                    feature.cipher_pubkey.append(cert_1.get_pubkey())
                    feature.cipher_serial_number.append(cert_1.get_serial_number())
                    if cert_1.get_subject() == cert_1.get_issuer():
                        # 自签名
                        feature.cipher_self_signature.append(1)
                    else:
                        # 非自签名
                        feature.cipher_self_signature.append(0)

            ans += certs

    return ans


def read_file(filename):
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            nth = 1
            time = 0
            global feature
            feature = featureType()
            feature.flag = True
            global flow
            flow = {}
            # feature.ip_src = filename.replace('.pcap', '').replace(base_dir, '')
            global contact
            contact = {}
            seq = []
            for timestamp, packet in capture:
                if nth == 1:
                    flag = timestamp
                time = timestamp - flag
                # if len(feature.content)<3:
                if feature.client_hello_content == bytes(0) or feature.server_hello_content == bytes(0) or feature.certificate_content == bytes(0):
                    analyze_packet(time, packet, nth)

                    nth += 1
                    seq.append(time)
                else:
                    break


            # flow 剩余解析certificate
            # if need_more_certificate:
            #     for key, value in flow.items():
            #         if len(value.data) != 0:
            #             tem = value.data
            #             if tem[0] in {20, 21, 22}:
            #                 parse_tls_records(tem, value.nth_seq[-1], value.nth_seq)
            # feature.pack_num = nth
            # feature.time = time
            # while len(feature.sequence) < 20:
            #     feature.sequence.append(0)
            f.close()
    except IOError:
        print('could not parse {0}'.format(filename))


def pre_flow(base_dir, save_dir, label):
    i = 0
    dataset = []

    for filename in tqdm(os.listdir(base_dir)):
        i += 1
        read_file(base_dir + filename)
        feature.name = filename.replace('.pcap', '')
        feature.label = label
        dataset.append(feature.toCut())
        # if i % 50 == 0:
        #     print(i)
    dataset_np = np.array(dataset)
    np.save(save_dir, dataset_np)


def pre_pcap(base_dir, save_dir, type):
    name_list = []
    black_list = []
    white_list = []
    with open("data/eta/datacon_eta/test_label/black.txt") as f:
        list = f.readlines()
        for key in list:
            black_list.append(key.strip('\n'))
    f.close()
    with open("data/eta/datacon_eta/test_label/white.txt") as f:
        list = f.readlines()
        for key in list:
            white_list.append(key.strip('\n'))
    f.close()

    dataset = []
    i = 0
    for filename in os.listdir(base_dir):
        i += 1
        if filename.replace('.pcap', '') not in name_list:
            read_file(base_dir + filename)
            need_more_certificate = True
            feature.name = filename.replace('.pcap', '')
            feature.label = type
            if type == 'test':
                if feature.name in black_list:
                    feature.label = "black"
                elif feature.name in white_list:
                    feature.label = "white"
                else:
                    print(feature.name)
            dataset.append(feature.toCut())
        if i % 50 == 0:
            print(i)
    dataset_np = np.array(dataset)
    np.save(save_dir, dataset_np)
    # with open("feature_base/feature_train_white.csv", "a+") as f:
    #     f_csv = csv.writer(f)
    #     for i,key in enumerate(dataset):
    #         f_csv.writerow(key)
    #         if i % 100 ==0:
    #             print(i)
    print("data collect end")
    return dataset


def main():

    dataset = []
    i = 0
    # base_dir = "data/eta/datacon_eta/test/"
    base_dir = "data/eta/datacon_eta/train/black/"
    # base_dir = 'data/eta_flow/train/white/'
    # base_dir = "data/eta/datacon_eta/train/white/"
    # base_dir = "data/资格赛数据分析/"
    # base_dir = 'data/eta/datacon_eta/train/white/'
    read_file(base_dir + '192.168.109.33.pcap')
    # feature.toCut()
    print(feature.content)
    feature.toSeq()

    # for filename in os.listdir(base_dir):
    #     i += 1
    #     num += 1
    #     # filename = "192.168.168.108.pcap" # 并行重传
    #     # filename =  "192.168.225.157.pcap" # udp
    #     read_file(base_dir + filename)
    #     if feature.cipher_application_data != 0:
    #         app_num += 1
    #
    #     feature.name = filename.replace('.pcap', '')
    #     dataset.append(feature.tolist())



if __name__ == "__main__":
    print("begin")
    # main()
    pre_flow("data/eta_flow/train/black/", 'f_data_content_1/train_black.npy', 'black')
    pre_flow("data/eta_flow/train/white/", 'f_data_content_1/train_white.npy', 'white')
    pre_flow("data/eta_flow/test/black/", 'f_data_content_1/test_black.npy', 'black')
    pre_flow("data/eta_flow/test/white/", 'f_data_content_1/test_white.npy', 'white')
    #
    # pre_pcap("data/eta/datacon_eta/train/black/", "feature_npy/train_black.npy", "black")
    # pre_pcap("data/eta/datacon_eta/train/white/", "feature_npy/train_white.npy", "white")
    # pre_pcap("data/eta/datacon_eta/test/", "feature_npy/test.npy", "test")
    print("end")