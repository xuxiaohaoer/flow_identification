# from __future__ import absolute_import
# from __future__ import print_function
import os
import socket
import json
import sys

import struct
from constants import PRETTY_NAMES
import numpy as np
from cipher_suite import cipher_suites
from cipher_suite import index
from math import pow
import dpkt
global contact
contact = {}

need_more_parse = True  # 需要更多TLS信息


class features(object):
    def __init__(self):
        self.ip_src = ''  # 目的ip地址
        self.ip_dst = ''  # 源ip地址
        self.dport = ''  # 源端口号
        self.sport = ''  # 目的端口号
        self.pack_num = 0  # 包数量
        self.flow_num = 0  # 流数目
        self.time = 0  # 整体持续时间
        self.time_sequence = []  # 时间序列
        self.max_time = 0  # 最大间隔时间
        self.min_time = 0  # 最小间隔时间
        self.mean_time = 0  # 平均间隔时间
        self.std_time = 0   # 均差间隔时间
        self.time_src_sequence = []  # 源时间间隔序列
        self.max_time_src = 0  # 最大源时间间隔
        self.min_time_src = 0  # 最小源时间间隔
        self.mean_time_src = 0  # 平均源时间间隔
        self.std_time_src = 0   # 均差源时间间隔
        self.time_dst_sequence = []  # 目的时间间隔序列
        self.max_time_dst = 0   # 最大目的时间间隔
        self.min_time_dst = 0   # 最小目的时间间隔
        self.mean_time_dst = 0  # 平均目的时间间隔
        self.std_time_dst = 0   # 均差目的时间间隔
        self.packetsize_src_sequence = []   # 源包大小序列
        self.max_packetsize_src = 0     # 最大源包大小
        self.min_packetsize_src = 0     # 最小源包大小
        self.mean_packetsize_src = 0    # 平均源包大小
        self.std_packetsize_src = 0     # 均差源包大小
        self.packetsize_dst_sequence = []   # 目的包大小序列
        self.max_packetsize_dst = 0     # 最大目的包大小
        self.min_packetsize_dst = 0     # 最小目的包大小
        self.mean_packetsize_dst = 0    # 均值目的包大小
        self.std_packetsize_dst = 0     # 均差目的包大小
        self.packetsize_flow_sequence = []  # 流大小序列
        self.max_packetsize_flow = 0  # 最大流大小
        self.min_packetsize_flow = 0  # 最小流大小
        self.mean_packetsize_flow = 0  # 平均流大小
        self.std_packetsize_flow = 0   # 均差流大小
        self.time_flow_sequence = []  # 流时间序列
        self.max_time_flow = 0  # 最大流时间
        self.min_time_flow = 0  # 最小流时间
        self.mean_time_flow = 0  # 平均流时间
        self.std_time_flow = 0  # 均差流时间
        self.packetsize_size = 0  # # 包大小
        self.packetsize_packet_sequence = []    # 包大小序列
        self.max_packetsize_packet = 0  # 最大包大小
        self.min_packetsize_packet = 0  # 最小包大小
        self.mean_packetsize_packet = 0  # 平均包大小
        self.std_packetsize_packet = 0  # 均差包大小
        self.sequence = []  # 自TLS开始的有向序列
        self.num = 0  # 数据流数量
        self.cipher_num = 0  # 加密组件长度
        self.cipher_support = []    # 加密支持组件序列
        self.cipher_support_num = 0  # 加密支持组件编码
        self.cipher = 0  # 加密组件
        self.name = ''  # pacp包名称
        self.cipher_content = [0 for i in range(256)]  # 加密内容里各字节出现次数
        self.cipher_content_ratio = 0   # 加密内容位中0出现次数
        self.flag = False
        self.urg = 0
        self.psh = 0


    def tolist(self):
        time = round(self.time)
        ip_src = int(self.ip_src.replace('.', ''))
        self.packetsize_size = round(self.packetsize_size / self.pack_num)
        self.max_time, self.min_time, self.mean_time, self.std_time = cal(self.time_sequence)
        self.max_packetsize_flow, self.min_packetsize_flow, self.mean_packetsize_flow, self.std_packetsize_flow = cal(self.packetsize_flow_sequence)
        self.max_time_flow, self.min_time_flow, self.mean_time_flow, self.std_time_flow =cal(self.time_flow_sequence)
        self.time_src_sequence = cal_seq(self.time_src_sequence)
        self.time_dst_sequence = cal_seq(self.time_dst_sequence)
        self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src = cal(self.time_src_sequence)
        self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst = cal(self.time_dst_sequence)
        self.max_packetsize_src, self.min_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src = cal(self.packetsize_src_sequence)
        self.max_packetsize_dst, self.min_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst = cal(self.packetsize_dst_sequence)
        self.max_packetsize_packet, self.min_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet = cal(self.packetsize_packet_sequence)
        self.cipher_support_num = cal_hex(self.cipher_support)
        self.cipher_content_ratio = round(cal_ratio(self.cipher_content), 4)
        # return [self.pack_num, time, self.dport, self.flow_num, ip_src, self.cipher_num, self.packetsize_size,
        #         self.max_time, self.min_time, self.mean_time, self.std_time, self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src,
        #         self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst, self.max_time_flow, self.min_time_flow, self.mean_time_flow, self.std_time_flow,
        #         self.max_packetsize_packet, self.min_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet,
        #         self.max_packetsize_src, self.min_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src,
        #         self.max_packetsize_dst, self.min_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst,
        #         self.max_packetsize_flow, self.min_packetsize_flow, self.mean_packetsize_flow, self.std_packetsize_flow,
        #         self.cipher, self.cipher_num, self.cipher_content_ratio
        #         ]
        return [self.pack_num, time, self.dport, self.flow_num, ip_src, self.cipher_num, self.packetsize_size,
                self.max_time, self.min_time, self.mean_time, self.std_time, self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src,
                self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst, self.max_time_flow, self.min_time_flow, self.mean_time_flow, self.std_time_flow,
                self.max_packetsize_packet,  self.mean_packetsize_packet, self.std_packetsize_packet,
                self.max_packetsize_src,  self.mean_packetsize_src, self.std_packetsize_src,
                self.max_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst,
                self.max_packetsize_flow, self.min_packetsize_flow, self.mean_packetsize_flow, self.std_packetsize_flow,
                self.cipher_num, self.cipher_content_ratio
                ]




class feature_type:
    def __init__(self, num, flow_size, flow_starttime, flow_endtime):
        self.num = num
        self.flow_size = flow_size
        self.flow_duration = 0
        self.flow_starttime = flow_starttime
        self.flow_endtime = flow_endtime



def cal(sequence):
    Max = max(sequence)
    Min = min(sequence)
    seq = np.array(sequence)
    mean = np.mean(seq)
    std = np.std(seq)
    return Max, Min, mean, std


def cal_seq(seq):
    tem = []
    for i, key in enumerate(seq):
        if i != 0:
            tem.append(key-seq[i-1])
    return tem


def cal_hex(seq):
    tem = []
    for key in seq:
        tem.append(hex(key))
    Sum = 0
    for key in tem:
        if key in cipher_suites:
            Sum += pow(2, cipher_suites[key])
    return Sum

def cal_ratio(seq):
    tem = 0
    total = 0
    for i, key in enumerate(seq):
        total += 4 * key
        tem += key * index[i]
    tem = tem / total
    return tem


def cal_psh(num):
    if num % 4 == 1:
        return True
    else:
        return False


def cal_urg(num):
    if num % 16 == 1:
        return True
    else:
        return False


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
    if isinstance(eth.data, dpkt.ip.IP):
        parse_ip_packet(eth, nth, timestamp)


def parse_ip_packet(eth, nth, timestamp):
    """
    Parses IP packet.
    """
    ip = eth.data
    sys.stdout.flush()
    size = len(eth)  # 包大小
    feature.packetsize_packet_sequence.append(size)

    if cal_psh(ip.data.flags):
        feature.psh += 1
    if cal_urg(ip.data.flags):
        feature.urg += 1

    if socket.inet_ntoa(ip.src) == feature.ip_src:
        feature.time_src_sequence.append(timestamp)
        feature.packetsize_src_sequence.append(size)
    else:
        feature.time_dst_sequence.append(timestamp)
        feature.packetsize_dst_sequence.append(size)
    payload = len(ip.data.data)  # 有效负载大小
    flag = socket.inet_ntoa(ip.src) + ' ' + socket.inet_ntoa(ip.dst) + ' ' + str(ip.data.dport) + ' ' + str(
        ip.data.sport)
    flag_1 = socket.inet_ntoa(ip.dst) + ' ' + socket.inet_ntoa(ip.src) + ' ' + str(ip.data.sport) + ' ' + str(
        ip.data.dport)
    if contact.__contains__(flag):
        contact[flag].num += 1
        contact[flag].flow_endtime = timestamp
        contact[flag].flow_size += size
    elif contact.__contains__(flag_1):
        contact[flag_1].num += 1
        contact[flag_1].flow_endtime = timestamp
        contact[flag_1].flow_size += size
    else:
        tem = feature_type(0, size, timestamp, timestamp)
        contact[flag] = tem
    feature.packetsize_size += size
    if isinstance(ip.data, dpkt.tcp.TCP) and payload:
        parse_tcp_packet(ip, nth, timestamp)
        for key in ip.data.data:
            feature.cipher_content[key] += 1
        if socket.inet_ntoa(ip.src) == feature.ip_dst:
            dir = 1
        else:
            dir = -1
        Dir = dir * payload
        if len(feature.sequence) < 20:
            feature.sequence.append(Dir)



def parse_tcp_packet(ip, nth, timestamp):
    """
    Parses TCP packet.
    """
    stream = ip.data.data
    ip.data.__flags__
    # ssl flow
    if (stream[0]) in {20, 21, 22, 23, 128, 25}:
        if (stream[0]) in {20, 21, 22}:
            parse_tls_records(ip, stream, nth)
        if (stream[0]) == 128:  # sslv2 client hello
            # feature.flag = True
            if len(stream) > 6:
                length = stream[6]
                feature.cipher_num = max(length, feature.cipher_num)
                tem = stream[7] + 11
                i = 0
                while i < length:
                    cipher = 0
                    if tem + i + 2 < len(stream):
                        cipher = stream[tem+i+2] + stream[tem+i+1]*256 + stream[tem+i]*256*256
                    if cipher not in feature.cipher_support:
                        feature.cipher_support.append(cipher)
                    i += 3
                # print(nth, stream[6])
        if (stream[0]) == 25:
            parse_tls_records(ip, stream, nth)


def parse_tls_records(ip, stream, nth):
    """
    Parses TLS Records.
    """
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        return
    # connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip.src),
    #                                       ip.data.sport,
    #                                       socket.inet_ntoa(ip.dst),
    #                                       ip.data.dport)
    n = 0
    for record in records:
        record_type = pretty_name('tls_record', record.type)
        if record_type == 'handshake':
            feature.ip_dst = socket.inet_ntoa(ip.src)
            feature.dport = ip.data.dport
            handshake_type = ord(record.data[:1])
            packetsize = record.data
            if handshake_type == 2:  # server hello
                feature.flow_num += 1
                feature.cipher = (record.data[-2] + record.data[-3] * 256)
            if n == 0:
                if handshake_type == 1:  #  sslv3 tlsv1 client hello
                    # feature.flag = True
                    length = record.data[40 + record.data[38]]
                    feature.cipher_num = max(length, feature.cipher_num)
                    tem = 40 + record.data[38] + 1
                    i = 0
                    while i < length:
                        cipher = record.data[tem+i] * 256 + record.data[tem + i + 1]
                        if cipher not in feature.cipher_support:
                            feature.cipher_support.append(cipher)
                        i += 2

                    # print(nth, record.data[40])
        n += 1
        sys.stdout.flush()


def read_file(base_dir, filename):
    try:
        with open(filename, 'rb') as f:
            capture = dpkt.pcap.Reader(f)
            nth = 1
            time = 0
            global feature
            feature = features()
            feature.ip_src = filename.replace('.pcap', '').replace(base_dir, '')
            contact.clear()
            seq = []
            for timestamp, packet in capture:
                analyze_packet(timestamp, packet, nth)
                if nth == 1:
                    flag = timestamp
                time = timestamp - flag
                nth += 1
                seq.append(time)
            feature.time_sequence = cal_seq(seq)
            for key in contact:
                contact[key].duration = contact[key].flow_endtime - contact[key].flow_starttime
                feature.packetsize_flow_sequence.append(contact[key].flow_size)
                feature.time_flow_sequence.append(contact[key].duration)
            feature.pack_num = nth
            feature.time = time
            while len(feature.sequence) < 20:
                feature.sequence.append(0)
            f.close()
    except IOError:
        print('could not parse {0}'.format(filename))


def pre_pcap(base_dir):
    dataset = []
    i = 0
    for filename in os.listdir(base_dir):
        read_file(base_dir, base_dir + filename)
        feature.name = filename.replace('.pcap', '')
        dataset.append(feature.tolist())
    print("data collect end")
    return dataset


def main():
    dataset = []
    i = 0
    base_dir = "data/eta_1/train/black/"
    for filename in os.listdir(base_dir):
        # print(filename)
        i += 1
        if i == 100:
            break
        # filename = "192.168.133.165.pcap"
        # filename = "192.168.71.170.pcap"
        # filename = "192.168.0.233.pcap"
        # filenmae = "192.168.114.127.pcap"
        # filename = "192.168.193.239.pcap"
        read_file(base_dir, base_dir + filename)
        feature.name = filename.replace('.pcap', '')
        cal(feature.time_sequence)
        dataset.append(feature.tolist())


if __name__ == "__main__":
    main()
