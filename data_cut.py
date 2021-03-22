import dpkt
import os
import socket
class flow():
    def __init__(self, data):
        self.data = data


def main(dir, type):
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
    base_dir = "data/eta/datacon_eta/"
    dir = base_dir + dir
    for i, filename in enumerate(os.listdir(dir)):
        # if filename.replace('.pcap', '') in black_list:
        #     type = 'black'
        # elif filename.replace('.pcap', '') in white_list:
        #     type = 'white'
        # else:
        #     print(filename)
        if i % 100 == 0:
            print(i)
        if 'pcap' in filename:
            pcap_ana(dir + filename, type)

def flow_ana(flow_record, type):
    for key in flow_record:
        base_path = 'data/eta_flow/train/' + type + '/'
        if os.path.exists(base_path):
            path = base_path + '/' + str(key) + '.pcap'
        else:
            os.mkdir(base_path)
            path = base_path + '/' + str(key) + '.pcap'
        test = open(path, "ab")
        writer = dpkt.pcap.Writer(test)
        for record in flow_record[key]:
            eth = record[0]
            timestamp = record[1]
            writer.writepkt(eth, ts=timestamp)
        test.flush()
        test.close()


def pcap_ana(filename, type):
    with open(filename, 'rb') as f:
        capture = dpkt.pcap.Reader(f)
        flow_record = {}
        i = 0
        for timestamp, packet in capture:
            i += 1
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            try:
                flag = socket.inet_ntoa(ip.src) + '->' + socket.inet_ntoa(ip.dst)
                flag_rev = socket.inet_ntoa(ip.dst) + '->' + socket.inet_ntoa(ip.src)
                if flag in flow_record.keys():
                    flow_record[flag].append([eth, timestamp])
                elif flag_rev in flow_record.keys():
                    flow_record[flag_rev].append([eth, timestamp])
                else:
                    flow_record[flag] = []
                    flow_record[flag].append([eth, timestamp])
            except AttributeError:
                pass
            except:
                print(filename)
                pass

        flow_ana(flow_record, type)


if __name__ == "__main__":
    print('begin')
    # main('test/', '')
    main('train/white/', 'white')
    print('end')