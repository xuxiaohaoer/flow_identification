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

global contact
contact = {}


need_more_parse = True  # 需要更多TLS信息
need_more_certificate = True
need_http = True


class FeatureType(object):
    def __init__(self):
        self.ip_src = ''  # 目的ip地址
        self.ip_dst = ''  # 源ip地址
        self.dport = 0  # 源端口号
        self.sport = 0  # 目的端口号
        self.pack_num = 0  # 包数量
        self.flow_num = 0  # 流数目
        self.num_src = 0  # 源包数目
        self.num_dst = 0    # 目的包数目
        self.num_ratio = 0  # 上下行流量比
        self.size_src = 0   # 源总包大小
        self.size_dst = 0   # 目的总包大小
        self.size_ratio = 0  # 上下行包大小比
        self.by_s = 0   # 每秒字节传输速度
        self.pk_s = 0   # 每秒包传输速度
        self.time = 0  # 整体持续时间
        self.time_sequence = []  # 时间序列
        self.max_time = 0  # 最大间隔时间
        self.min_time = 0  # 最小间隔时间
        self.mean_time = 0  # 平均间隔时间
        self.std_time = 0  # 均差间隔时间
        self.time_src_sequence = []  # 源时间间隔序列
        self.max_time_src = 0  # 最大源时间间隔
        self.min_time_src = 0  # 最小源时间间隔
        self.mean_time_src = 0  # 平均源时间间隔
        self.std_time_src = 0  # 均差源时间间隔
        self.time_dst_sequence = []  # 目的时间间隔序列
        self.max_time_dst = 0  # 最大目的时间间隔
        self.min_time_dst = 0  # 最小目的时间间隔
        self.mean_time_dst = 0  # 平均目的时间间隔
        self.std_time_dst = 0  # 均差目的时间间隔
        self.packetsize_src_sequence = []  # 源包大小序列
        self.max_packetsize_src = 0  # 最大源包大小
        self.min_packetsize_src = 0  # 最小源包大小
        self.mean_packetsize_src = 0  # 平均源包大小
        self.std_packetsize_src = 0  # 均差源包大小
        self.packetsize_dst_sequence = []  # 目的包大小序列
        self.max_packetsize_dst = 0  # 最大目的包大小
        self.min_packetsize_dst = 0  # 最小目的包大小
        self.mean_packetsize_dst = 0  # 均值目的包大小
        self.std_packetsize_dst = 0  # 均差目的包大小
        self.packetsize_flow_sequence = []  # 流大小序列
        self.max_packetsize_flow = 0  # 最大流大小
        self.min_packetsize_flow = 0  # 最小流大小
        self.mean_packetsize_flow = 0  # 平均流大小
        self.std_packetsize_flow = 0  # 均差流大小
        self.time_flow_sequence = []  # 流时间序列
        self.max_time_flow = 0  # 最大流时间
        self.min_time_flow = 0  # 最小流时间
        self.mean_time_flow = 0  # 平均流时间
        self.std_time_flow = 0  # 均差流时间
        self.packetsize_size = 0  # # 平均包大小
        self.packetsize_packet_sequence = []  # 包大小序列
        self.max_packetsize_packet = 0  # 最大包大小
        self.min_packetsize_packet = 0  # 最小包大小
        self.mean_packetsize_packet = 0  # 平均包大小
        self.std_packetsize_packet = 0  # 均差包大小
        self.sequence = []  # 自TLS开始的有向序列
        self.payload_seq = []
        self.tls_seq = []
        self.dir_seq = []
        self.num = 0  # 数据流数量

        self.cipher_num = 0  # 加密组件长度
        self.cipher_support = []  # 加密支持组件序列
        self.cipher_support_num = 0  # 加密支持组件编码
        self.cipher = 0  # 加密组件
        self.cipher_content = [0 for i in range(256)]  # 加密内容里各字节出现次数
        self.cipher_content_ratio = 0  # 加密内容位中0出现次数

        self.certificate = []
        self.cipher_self_signature = []  # 是否自签名，是1，否为0
        self.cipher_certifcate_time = []  # 证书有效时间
        self.cipher_subject = []  # 证书中subject
        self.cipher_issue = []  # 证书中issue
        self.cipher_extension_count = []
        self.cipher_sigature_alo = []
        self.cipher_version = []
        self.cipher_pubkey = []
        self.cipher_serial_number = []
        self.cipher_application_data = 0
        self.flag = False  # 只取第一个certificate

        self.fin = 0  # 标志位Fin的数量
        self.syn = 0  # 标志位Syn的数量
        self.rst = 0  # 标志位RST的数量
        self.ack = 0  # 标志位ACK的数量
        self.urg = 0  # 标志位URG的数量
        self.psh = 0  # 标志位PSH的数量
        self.ece = 0  # 标志位ECE的数量
        self.cwe = 0  # 标志位CWE的数量

        self.transition_matrix = np.zeros((15, 15), dtype=int)  # 马尔可夫转移矩阵
        self.label = ''  # 若有，则为具体攻击类型
        self.name = ''  # pacp包名称

    def tolist(self):
        """change to list that is the model input"""
        # print(self.cipher_application_data)
        return[self.tls_seq, self.payload_seq, self.dir_seq, self.label, self.name]


class FlowRecord:
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
    if isinstance(tcp_data, dpkt.tcp.TCP):
        feature.fin += 1 if cal_fin(tcp_data.flags) else 0
        feature.syn += 1 if cal_syn(tcp_data.flags) else 0
        feature.rst += 1 if cal_rst(tcp_data.flags) else 0
        feature.psh += 1 if cal_psh(tcp_data.flags) else 0
        feature.ack += 1 if cal_ack(tcp_data.flags) else 0
        feature.urg += 1 if cal_urg(tcp_data.flags) else 0
        feature.cwe += 1 if cal_cwe(tcp_data.flags) else 0
        feature.ece += 1 if cal_ece(tcp_data.flags) else 0

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
        tem = FlowRecord(0, size, timestamp, timestamp)
        contact[flag] = tem
    feature.packetsize_size += size
    if isinstance(ip.data, dpkt.tcp.TCP) and payload:
        rest_load = parse_tcp_packet(ip, nth, timestamp)
        for key in ip.data.data:
            feature.cipher_content[key] += 1
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
            if data[0] in {20,21,22, 23}:
                data_tem, flag = parse_tls_records(data, nth, [nth])
                if  flag:
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
                    if tem[0] in {20, 21, 22, 23}:
                        rest_load, flag  = parse_tls_records(tem, nth_flag[-1], nth_flag)

                try:
                    if rest_load != None and not len(data_flag):
                        flow[flow_flag1].data = rest_load
                        if rest_load == bytes(0):
                            flow[flow_flag1].sequence.clear()
                            flow[flow_flag1].nth_seq.clear()
                        else:
                            # 中间插入一条ack较大值
                            flow[flow_flag1].sequence = [rest_load]
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
        if data == None:
            print(nth)

        if len(data):
            if flow_flag not in flow.keys():
                if data != bytes(0):
                    if data[0] in {20, 21, 22, 23}:
                        flow[flow_flag] = FlowFlag(seq, data)
                        flow[flow_flag].sequence.append(data)
                        flow[flow_flag].nth_seq.append(nth)
                        flow[flow_flag].seq_exp = seq + len(data_flag)
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
                else:
                    pass
    # if nth == 49:
    #     print(len(flow["217.69.139.110->192.168.44.25"].sequence))
    #     print(flow["217.69.139.110->192.168.44.25"].sequence)
    #     print(flow["217.69.139.110->192.168.44.25"].nth_seq)




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
                length = stream[6] + stream[5] * 256
            except:
                length = 0
            if len(stream) > 6:
                if stream[2] == 1:  # sslv2 client hello
                    feature.tls_seq[nth-1] = stream[2]
                    feature.cipher_num = max(length, feature.cipher_num)
                    tem = stream[6]*256 + stream[7] + 11  # 加密组件开始的stream的index
                    i = 0
                    while i < length:
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

def multiple_handshake(nth,buf):
    i, n = 0, len(buf)
    msgs = []
    while i + 5 <= n:
        tot = 0
        v = buf[i + 1:i + 3]
        if v in dpkt.ssl.SSL3_VERSION_BYTES:
            head = buf[i:i+5]
            tot_len = int.from_bytes(buf[i+3:i+5], byteorder='big')
            j = i+5
            while j<= tot_len +1:
                try:
                    Record_len = int.from_bytes(buf[j+1:j+4], byteorder='big',signed=False)
                    len_tem_b = (Record_len +4).to_bytes(length=2, byteorder='big', signed=False)
                    head_tem = head[0:3] + len_tem_b
                    tem = head_tem + buf[j:j+Record_len+4]
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
                        elif handshake_type == 2: # server hello
                            pass


                    # print(nth, "***{}***".format(msg))

                except dpkt.NeedData:
                    pass
                try:
                    j += Record_len + 4
                    i += j
                except :
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


def parse_tls_records(stream, nth, nth_seq):
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
            records, bytes_used =multiple_handshake(nth, stream)
            flag = True
        except:
            return stream, False
        if bytes_used > len(stream):
            return stream, False

    # multiple 只解压了第一个报文
    try:
        record_len = int.from_bytes(records[0].data[1:4], byteorder='big')
        handshake_type = records[0].data[0]
        # 握手格式要求，避免加入application data等信息
        if handshake_type in {1,2,11,12,14,16,20,21,23}:
            if record_len + 4 < records[0].length:
                flag = True
                records, bytes_used = multiple_handshake(nth, stream)
    except:
        return stream, False
    flag = True

    n = 0
    type = []
    handshake_scope = [1,2,11,12,14,16]
    for record in records:
        # print(nth, record.version)
        record_type = pretty_name('tls_record', record.type)


        if record_type == 'application_data':
            i = (len(stream)- bytes_used) // 1460

            print(i)
            print(nth, nth_seq[-1-i],record_type)
            # print(record.data[-1])
            feature.cipher_application_data += 1

        if record_type == 'handshake':
            handshake_type = ord(record.data[:1])
            if handshake_type in handshake_scope:
                type.append(handshake_type)
            # print(nth, "handshake_type", handshake_type)
            if handshake_type == 2:  # server hello
                feature.flow_num += 1
                feature.cipher = (record.data[-2] + record.data[-3] * 256)
            if handshake_type == 11:  # certificate
                len_cer = int.from_bytes(record.data[4:7], byteorder='big')  # 转换字节流为十进制
                data = record.data[7:]
                tem = 0
                a = []
                a = parse_tls_certs(nth, record.data, record.length)
                while len(data):
                    len_cer_tem = int.from_bytes(data[0:3], byteorder='big')
                    certificate = data[3:len_cer_tem + 3]
                    data = data[len_cer_tem + 3:]
            if n == 0:
                if handshake_type == 1:  # sslv3 tlsv1 client hello
                    # feature.flag = True
                    try:
                        length = int(record.data[40 + record.data[38]])
                    except IndexError as exception:
                        length = 0
                        print(feature.name)
                    feature.cipher_num = max(length, feature.cipher_num)
                    tem = 40 + record.data[38] + 1
                    i = 0
                    while i < length:
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
        feature.tls_seq[nth-1] = type
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
            feature = FeatureType()
            feature.flag = True
            global flow
            flow = {}
            # feature.ip_src = filename.replace('.pcap', '').replace(base_dir, '')
            contact.clear()
            seq = []
            for timestamp, packet in capture:
                # print(nth)
                if feature.flag:
                    analyze_packet(timestamp, packet, nth)
                if nth == 1:
                    flag = timestamp
                time = timestamp - flag
                nth += 1
                seq.append(time)
            feature.time_sequence = cal_seq(seq)
            for key in contact:
                # print(key)
                # print(key.find(feature.ip_src))
                contact[key].duration = contact[key].flow_endtime - contact[key].flow_starttime
                feature.packetsize_flow_sequence.append(contact[key].flow_size)
                feature.time_flow_sequence.append(contact[key].duration)
            # flow 剩余解析certificate
            if need_more_certificate:
                for key, value in flow.items():
                    if len(value.data) != 0:
                        tem = value.data
                        if tem[0] in {20, 21, 22}:
                            parse_tls_records(tem, value.nth_seq[-1], value.nth_seq)
            feature.pack_num = nth
            feature.time = time
            while len(feature.sequence) < 20:
                feature.sequence.append(0)
            f.close()
    except IOError:
        print('could not parse {0}'.format(filename))


def pre_pcap(base_dir, save_dir, type):
    name_list =[]
    null_list = []
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
            dataset.append(feature.tolist())
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
    print("begin")
    dataset = []
    i = 0
    # base_dir = "data/eta/datacon_eta/test/"
    # base_dir = "data/eta/datacon_eta/train/black/"
    # base_dir = 'data/eta_flow/train/white/'
    # base_dir = "data/eta/datacon_eta/train/white/"
    base_dir = "data/资格赛数据分析/"
    # base_dir = 'data/eta/datacon_eta/train/white/'
    read_file(base_dir + '192.168.44.25.pcap')

    # for filename in os.listdir(base_dir):
    #     i += 1
    #     num += 1
    #     # filename = "192.168.133.165.pcap"
    #     # filename = "192.168.71.170.pcap"
    #     # filename = "192.168.0.233.pcap"
    #     # filename = "192.168.114.127.pcap"
    #     # filename = "192.168.193.239.pcap"
    #     # filename = "192.168.0.233.pcap"
    #     # filename = "192.168.253.95.pcap"
    #     # filename = "192.168.163.190.pcap"
    #     # filename = "192.168.168.108.pcap" # 并行重传
    #     # filename =  "192.168.225.157.pcap" # udp
    #     # filename = "192.168.201.173.pcap"
    #     read_file(base_dir + filename)
    #     if feature.cipher_application_data != 0:
    #         app_num += 1
    #
    #     feature.name = filename.replace('.pcap', '')
    #     dataset.append(feature.tolist())
    print("end")


if __name__ == "__main__":
    main()
    # pre_pcap("data/eta/datacon_eta/train/black/", "behavior/black_2.npy", "black")
    # pre_pcap("data/eta/datacon_eta/train/white/", "behavior/white_2.npy", "white")
    # pre_pcap("data/eta/datacon_eta/test/", "behavior/test_2.npy", "test")
