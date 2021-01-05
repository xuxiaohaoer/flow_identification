#encoding=utf-8
import scapy.all as scapy
import scapy.data

import os
def main():
    base_dir = "data/资格赛数据分析/"
    # for file in os.listdir(base_dir):
    file = "192.168.10.91.pcap"
    dir = base_dir + file
    packets = scapy.rdpcap(dir)  # 读取pcap文件
    for nth,packet in enumerate(packets):
        print(nth, packet)
        print (packet.show())


if __name__ == "__main__":
    main()