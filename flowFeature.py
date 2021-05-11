import  numpy as np
import math
from cal import *
class featureType(object):
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

        self.bitFre = np.zeros(256) # 所有负载内各字节出现次数
        self.entropy = 0
        self.entropy_seq = []
        self.max_entropy = 0
        self.min_entropy = 0
        self.mean_entropy = 0
        self.std_entropy = 0


        self.cipher_num = 0  # 加密组件长度
        self.cipher_support = []  # 加密支持组件序列
        self.cipher_support_num = 0  # 加密支持组件编码
        self.cipher = 0  # 加密组件
        self.cipher_app_content = bytes(0)
        self.cipher_bitFre = np.zeros(256)  # 加密内容里各字节出现次数

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

        self.cipher_entropy = 0 # 总熵值
        self.cipher_app_num = 0 # 加密应用数据数目
        self.cipher_app_entropy = [] # 加密内容熵序列

        self.max_cipher_app_entropy = 0
        self.min_cipher_app_entropy = 0
        self.mean_cipher_app_entropy = 0
        self.std_cipher_app_entropy = 0

        self.flag = False  # 只取第一个certificate

        self.fin = 0  # 标志位Fin的数量
        self.syn = 0  # 标志位Syn的数量
        self.rst = 0  # 标志位RST的数量
        self.ack = 0  # 标志位ACK的数量
        self.urg = 0  # 标志位URG的数量
        self.psh = 0  # 标志位PSH的数量
        self.ece = 0  # 标志位ECE的数量
        self.cwe = 0  # 标志位CWE的数量

        self.client_hello_content = bytes(0)
        self.server_hello_content = bytes(0)
        self.certificate_content = bytes(0)

        self.transition_matrix = np.zeros((15, 15), dtype=int)  # 马尔可夫转移矩阵
        self.label = ''  # 若有，则为具体攻击类型
        self.name = ''  # pacp包名称

        self.content = [] # 包负载内容
        self.content_payload = []



    def tolist(self):
        """change to list that is the model input"""
        # print(self.cipher_application_data)
        # 存在application data

        time = round(self.time)
        ip_src = int(self.ip_src.replace('.', ''))
        self.packetsize_size = round(self.packetsize_size / self.pack_num)
        self.max_time, self.min_time, self.mean_time, self.std_time = cal(self.time_sequence)
        self.max_packetsize_flow, self.min_packetsize_flow, self.mean_packetsize_flow, self.std_packetsize_flow = cal(
            self.packetsize_flow_sequence)
        self.max_time_flow, self.min_time_flow, self.mean_time_flow, self.std_time_flow = cal(self.time_flow_sequence)
        self.time_src_sequence = cal_seq(self.time_src_sequence)
        self.time_dst_sequence = cal_seq(self.time_dst_sequence)
        self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src = cal(self.time_src_sequence)
        self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst = cal(self.time_dst_sequence)
        self.max_packetsize_src, self.min_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src = cal(
            self.packetsize_src_sequence)
        self.max_packetsize_dst, self.min_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst = cal(
            self.packetsize_dst_sequence)
        self.max_packetsize_packet, self.min_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet = cal(
            self.packetsize_packet_sequence)
        self.cipher_support_num = cal_hex(self.cipher_support)
        self.cipher_content_ratio = round(cal_ratio(self.bitFre), 4)
        self.transition_matrix = cal_matrix(self.packetsize_packet_sequence)
        self.num_ratio = cal_div(self.num_src, self.num_dst)
        self.size_ratio = cal_div(self.size_src, self.num_dst)
        self.by_s = cal_div(self.packetsize_size, self.time)
        self.pk_s = cal_div(self.pack_num, self.time)

        self.max_entropy, self.min_entropy, self.mean_entropy, self.std_entropy = cal(self.bitFre)
        self.max_cipher_app_entropy, self.min_cipher_app_entropy, self.mean_cipher_app_entropy, self.std_cipher_app_entropy = cal(self.cipher_bitFre)
        # if self.cipher_bitFre.sum() != 0:
        #     self.cipher_bitFre /= self.cipher_bitFre.sum()
        #     self.cipher_entropy = self.cal_entropy(self.cipher_bitFre)
        # if self.bitFre.sum() != 0:
        #     self.bitFre /= self.bitFre.sum()
        #     self.entropy = self.cal_entropy(self.bitFre)

        return [self.pack_num, time, self.flow_num, ip_src, self.packetsize_size, self.dport,
                # 5
                self.max_time, self.min_time, self.mean_time, self.std_time,
                self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src,
                self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst,
                self.max_time_flow, self.min_time_flow, self.mean_time_flow, self.std_time_flow,
                # 21
                self.max_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet,
                self.max_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src,
                self.max_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst,
                self.max_packetsize_flow, self.min_packetsize_flow, self.mean_packetsize_flow, self.std_packetsize_flow,
                # 34
                self.fin, self.syn, self.rst, self.ack, self.urg, self.psh, self.ece, self.cwe,
                # 42
                self.num_src, self.num_dst, self.num_ratio,
                self.size_src, self.size_dst, self.size_ratio,
                self.by_s, self.pk_s,
                # 50
                self.cipher_self_signature, self.cipher_certifcate_time, self.cipher_subject,
                self.cipher_issue, self.cipher_extension_count, self.cipher_sigature_alo, self.cipher_version,
                self.cipher_num, self.cipher_support, self.cipher_support_num, self.cipher,
                self.cipher_content_ratio,
                self.cipher_app_num,
                # 63
                self.transition_matrix,
                self.tls_seq, self.payload_seq, self.dir_seq,
                self.label, self.name
                ]
        # self.entropy, self.bitFre, self.max_entropy, self.min_entropy, self.mean_entropy, self.std_entropy,
        # # 69
        # self.cipher_entropy, self.cipher_bitFre, self.max_cipher_app_entropy, self.min_cipher_app_entropy, self.mean_cipher_app_entropy, self.std_cipher_app_entropy

    def toSeq(self):
        contents = []
        for key in self.content:
            content = []
            for value in key:
                content.append(value/255)
            content += [0]* 144
            contents.append(content[:144])
        while len(contents)<3:
            contents.append([0]*144)
        while len(self.content_payload) <3:
            self.content_payload.append(0)
        # print(contents)
        return [contents, self.content_payload, self.label, self.name]

    def toCut(self):
        contents = []
        contents.append(self.client_hello_content )
        contents.append(self.server_hello_content )
        contents.append(self.certificate_content)

        return [contents, self.label, self.name]

    def cal_entropy(self, content):
        result = 0
        for key in content:
            if key != 0 :
                result += (-key) * math.log(key, 2)
        return result

