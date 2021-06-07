from sklearn.preprocessing import OneHotEncoder
import csv
import numpy as np


def data_read_flow():
    dataset_b = np.load("feature_flow/train_black.npy", allow_pickle=True)
    dataset_w = np.load("feature_flow/train_white.npy", allow_pickle=True)
    dataset_t_b = np.load("feature_flow/test_black.npy", allow_pickle=True)
    dataset_t_w = np.load("feature_flow/test_white.npy", allow_pickle=True)
    dataset_t = dataset_t_b + dataset_t_w

    return dataset_b, dataset_w, dataset_t

def data_read():
    dataset_b = np.load("feature_npy/train_black.npy", allow_pickle=True)
    dataset_w = np.load("feature_npy/train_white.npy", allow_pickle=True)
    dataset_t = np.load("feature_npy/test.npy", allow_pickle=True)

    return dataset_b, dataset_w, dataset_t

def list_string(tem):
    # 存储后的list的字符串转化为list
    tem = tem.strip('[').strip(']')
    tem = tem.replace(' ', '')
    tem = tem.replace("'", '')
    return list(tem.split(','))

def find_first(tem):
    # 寻找第一个值
    if len(tem) != 0:
        return tem[0]
    else:
        return ''


def find_min(tem):
    if len(tem) != 0:
        return min(tem)
    else:
        return 0

def find_self_signed(tem):
    if len(tem) != 0:
        if '1' in tem:
            return 1
        else:
            return 0
    else:
        return 0

def Find_first(tem):
    if tem == []:
        return ''
    else:
        return tem[0]
def oh_encoding(tem):
    encoder = OneHotEncoder(sparse=False)
    return encoder.fit_transform(np.array(tem).reshape(-1, 1))

def len_handle(tem, length):
    while len(tem) <= length:
        tem.append(0)
    return tem[:length]


def mix(beh, pay, length):
    for i in range(length):
        if beh[i] != 0:
            # beh[i] += 1
            pass
        else:
            if pay[i]!= 0:
                beh[i] +=1
    return beh

def mix_flag(beh, pay, length):
    for i in range(length):
        if beh[i] == 0:
            beh[i] = pay[i]
    return beh

def mix_dir(beh, pay, dir, length):
    for i in range(length):
        if beh[i] == 0:
            beh[i] = pay[i]
        beh[i] *= dir[i]
    return beh


def find_state(tem):
    state = {'0': 0,
             '1': 11,
             '2': 12, '2->11': 13, '2->11->12->14': 14, '2->11->12->14->14': 15, '2->11->14': 16, '2->11->14->14': 17,
             '2->20': 18, '2->20->1':19,'2->20->2':20, '2->20->11': 21, '2->20->14': 22, '2->20->16':23 , '2->20->12': 24, '2->20->23': 25, '2->20->23->23->23->23':26,
             '11': 27, '11->12': 28, '11->12->14': 29, '11->14': 30, '11->16->20': 31, '11->16->20->11': 32,
             '12':33, '12->14': 34,
             '14': 35,
             '16': 36, '16->20': 37, '16->20->1': 38, '16->20->2': 39, '16->20->2->2':40, '16->20->11': 41, '16->20->11->11':42, '16->20->12': 43, '16->20->12->12':44, '16->20->14->14':45, '16->20->16->16':46,
             '16->20->14': 47, '16->20->16': 48,
             '20': 49, '20->1': 50, '20->2': 51, '20->11': 52, '20->12': 53, '20->14': 54, '20->16': 55, '20->21': 56,
             '20->23': 57, '20->23->21': 58, '20->23->23': 59,
             '21': 60, '21->21': 61}
    if type(tem) == list:
        if tem != []:
            str_flag = ''
            for flag in tem:
                str_flag += str(flag) + '->'
            str_flag = str_flag.rstrip('->')
        else:
            str_flag = '0'
    else:
        str_flag = str(tem)
    return state[str_flag]

def find_state_1(tem):
    state = {'0': 0,
             '1': 11,
             '2': 12, '11': 13, '12':14,
             '14': 15,
             '16': 16,
             '20': 17,
             '21': 18,
             '23': 19}

    return state[str(tem)]

def expand(beh, pay, dir, flag, length):
    seq = []
    if flag != 'dir':
        for i,value in enumerate(len_handle(beh, length)):
            tem = 0
            if type(value) == list:
                if value != []:
                    for key in value:
                        seq.append(find_state_1(key))
                else:
                    tem = 0
            else:
                tem = find_state_1(value)
            if tem != 0:
                seq.append(tem)
            else:
                # 删除tcp握手
                if (pay[i]!= 0 ):
                    seq.append(pay[i])
                else:
                    pass
    else:
        for i, value in enumerate(len_handle(beh, length)):
            tem = 0
            if type(value) == list:
                if value != []:
                    for key in value:
                        seq.append(dir[i]*find_state_1(key))
                else:
                    tem = 0
            else:
                tem = dir[i]*find_state_1(value)
            if tem != 0:
                seq.append(tem)
            else:
                if (pay[i]!=0):
                    seq.append(dir[i]*pay[i])
                else:
                    pass
    return seq

def find_pay(tem, length):
    """

    :param tem:
    :param length: 切割长度
    :return:
    """
    seq = []
    for key in tem:
        flag = key // length
        # if flag >10:
        #     flag = 10
        seq.append(flag)
    return seq

def pre_data_payload(length, length_1):
    """

    :param length: 传输进来长度
    :param length_1: 切割负载的size
    :return:
    """
    dataset_b = np.load("../datacon/behavior/black_2.npy", allow_pickle=True)
    dataset_w = np.load("../datacon/behavior/white_2.npy", allow_pickle=True)
    dataset_t = np.load("../datacon/behavior/test_2.npy", allow_pickle=True)
    dataset = np.vstack((dataset_b, dataset_w, dataset_t))
    label = []
    payload = []
    pay_max = 1460
    for key in dataset:
        if key[-2] == 'black':
            label.append(1)
        elif key[-2] == 'white':
            label.append(0)
        else:
            label.append(0)
        pay = len_handle(key[1], length)
        payload.append(find_pay(pay, length_1))
    ratio = len(dataset_w) + len(dataset_b)
    return payload[:ratio], payload[ratio:], label[:ratio], label[ratio:]



def pre_data_test(flag, length, model):
    dataset_b = np.load("../datacon/behavior/black_2.npy", allow_pickle=True)
    dataset_w = np.load("../datacon/behavior/white_2.npy", allow_pickle=True)
    dataset_t = np.load("../datacon/behavior/test_2.npy", allow_pickle=True)
    dataset = np.vstack((dataset_b, dataset_w, dataset_t))
    if model == 'AE':
        d_b, d_w = [], []
        for key in dataset:
            if key[-2] == 'black':
                d_b.append(key)
            else:
                d_w.append(key)
        dataset = np.vstack((d_w, d_b))
    behavior = []
    behavior_1 = []
    payload = []
    print("length:{}".format(length))
    label = []
    matrix = []
    mix_seq = []
    mix_seq_dir = []
    mix_seq_1 = []
    mix_seq_dir_1 = []
    max_flag = 0
    beh_tests = []
    direction = []
    message1 = []
    message2 = []
    tot = 0
    for key in dataset:
        if key[-2] == 'black':
            label.append(1)
        elif key[-2] == 'white':
            label.append(0)
        else:
            label.append(0)
        if max_flag < max(key[1]):
            max_flag = max(key[1])

        pay = len_handle(key[1], length)
        # pay = find_pay(pay)
        payload.append(pay)

        dir = len_handle(key[2], length)
        direction.append(dir)

        beh = []
        beh1 = []
        for value in len_handle(key[0], length):
            beh.append(value)
        print(key[0])
        for value in key[0]:
            if type(value) != int:
                for key in value:
                    if key == 23:
                        tot += 1
            else:
                if value == 23:
                        tot +=1
        #
        # for value in len_handle(key[0], length):
        #     if type(value) == list:
        #         if value != []:
        #             tem = value[0]
        #         else:
        #             tem = 0
        #     else:
        #         tem = value
        #     beh1.append(find_state_1(tem))
        behavior.append(beh)
        # behavior_1.append(beh1)

        # if type(key[0]) == list:
        #     tem = int( key[0][0])
        # else:
        #     tem = int(key[0])
        # behavior.append(tem)
    print(tot)
    print("this is made by {}".format(flag))
    ratio = len(dataset_w) + len(dataset_b)
    if model == 'AE':
        if flag == "behavior":
            return behavior[:4000], behavior[4000:], label[:4000], label[4000:]
        elif flag == "payload":
            return payload[:4000], payload[4000:], label[:4000], label[4000:]
        elif flag == "matrix":
            return matrix[:4000], matrix[4000:], label[:4000], label[4000:]
        elif flag == 'mix_seq':
            return mix_seq[:4000], mix_seq[4000:], label[:4000], label[4000:]
    else:
        if flag == "behavior":
            return behavior[:ratio], behavior[ratio:], label[:ratio], label[ratio:]
        elif flag == "payload":
            return payload[:ratio], payload[ratio:], label[:ratio], label[ratio:]
        elif flag == "direction":
            return direction[:ratio], direction[ratio:], label[:ratio], label[ratio:]
        elif flag == 'behavior1':
            return behavior_1[:ratio], behavior_1[ratio:], label[:ratio], label[ratio:]



def pre_data_beh(flag ,length, model):
    """
    :param flag:选取特征
    :param length: 截取长度
    :param model: 是否为AE
    :return: 数据集
    mix_seq:
    mix_seq_1:
    mix_dir:
    mix_dir_1:
    matrix:
    """
    dataset_b = np.load("../datacon/behavior/black_2.npy", allow_pickle=True)
    dataset_w = np.load("../datacon/behavior/white_2.npy", allow_pickle=True)
    dataset_t = np.load("../datacon/behavior/test_2.npy", allow_pickle=True)
    dataset = np.vstack((dataset_b, dataset_w, dataset_t))
    if model == 'AE':
        d_b, d_w = [], []
        for key  in dataset:
            if key[-2] == 'black':
                d_b.append(key)
            else:
                d_w.append(key)
        dataset = np.vstack((d_w, d_b))
    behavior = []
    payload = []
    print("length:{}".format(length))
    label = []
    matrix = []
    mix_seq = []
    mix_seq_dir = []
    mix_seq_1 = []
    mix_seq_dir_1 = []
    max_flag = 0
    beh_tests = []
    for key in dataset:
        if key[-2] == 'black':
            label.append(1)
        elif key[-2] == 'white':
            label.append(0)
        else:
            label.append(0)
        if max_flag< max(key[1]):
            max_flag  = max(key[1])

        pay = len_handle(key[1], length)
        pay1 = pay
        pay = find_pay(pay, 146)
        payload.append(pay1)
        beh = []
        dir = len_handle(key[2], length)
        mix_seq_1.append(len_handle(expand(key[0], pay, dir, '', length),length))
        mix_seq_dir_1.append(len_handle(expand(key[0], pay, dir, 'dir', length), length))
        for value in len_handle(key[0], length):
            beh.append(find_state(value))
        mix_seq.append(mix_flag(beh, pay, length))
        mix_seq_dir.append(mix_dir(beh, pay, dir, length))
        behavior.append(beh)
        matrix.append(np.hstack((beh,pay1)))
        # if type(key[0]) == list:
        #     tem = int( key[0][0])
        # else:
        #     tem = int(key[0])
        # behavior.append(tem)
    print("this is made by {}".format(flag))
    ratio = len(dataset_w) + len(dataset_b)
    if model == 'AE':
        if flag == "behavior":
            return behavior[:4000], behavior[4000:], label[:4000], label[4000:]
        elif flag == "payload":
            return payload[:4000], payload[4000:], label[:4000], label[4000:]
        elif flag == "matrix":
            return matrix[:4000], matrix[4000:], label[:4000], label[4000:]
        elif flag == 'mix_seq':
            return mix_seq[:4000], mix_seq[4000:], label[:4000], label[4000:]
    else:
        if flag == "behavior":
            return behavior[:ratio], behavior[ratio:], label[:ratio], label[ratio:]
        elif flag == "payload":
            return payload[:ratio], payload[ratio:], label[:ratio], label[ratio:]
        elif flag == "matrix":
            return matrix[:ratio], matrix[ratio:], label[:ratio], label[ratio:]
        elif flag == 'mix_seq':
            return mix_seq[:ratio], mix_seq[ratio:], label[:ratio], label[ratio:]
        elif flag == 'mix_seq_1':
            return mix_seq_1[:ratio], mix_seq_1[ratio:], label[:ratio], label[ratio:]
        elif flag == 'mix_seq_dir':
            return mix_seq_dir[:ratio], mix_seq_dir[ratio:], label[:ratio], label[ratio:]
        elif flag == 'mix_seq_dir_1':
            return mix_seq_dir_1[:ratio], mix_seq_dir_1[ratio:], label[:ratio], label[ratio:]




def pre_data(flag, type):
    if type == 'flow':
        dataset_b, dataset_w, dataset_t = data_read_flow()
    else:
        dataset_b, dataset_w, dataset_t= data_read()

    dataset = np.vstack((dataset_b,dataset_w, dataset_t))
    print(dataset.shape)
    # 前6000 训练集合，后4000测试集合
    time = []
    # 6-21
    payload = []
    # 22-34
    tcp_flag = []
    # 35-42
    cipher = []
    # subject,issue, certificate_time. self_signed, cipher_num(58), cipher(61) ,cipher_content_ratio(63) cipher_version
    speed = []
    # 43 - 50
    ip = []
    subject = []
    issue = []
    cipher_version = []
    label = []
    matrix = []
    flow = []

    # 65
    bitFre = []
    entropy = []
    cipher_bifFre = []
    cipher_entropy = []
    label_e = []
    for key in dataset:

        flow_one = []
        for j in range(0,3):
            flow_one.append(float(key[j]))
        for j in range(4,51):
            flow_one.append(float(key[j]))
        certificate_time = int(find_min((key[52])))
        # certificate_time
        self_signed = find_self_signed((key[51]))
        # 自签名
        flow_one.append(certificate_time)
        flow_one.append(self_signed)
        flow.append(flow_one)

        cipher_one = []
        cipher_one.append(key[58])
        cipher_one.append(key[61])
        cipher_one.append(key[63])

        time.append(key[6:22])
        tcp_flag.append(key[35:43])
        payload.append(key[22:35])
        speed.append(key[43:51])
        if key[-2] == 'black':
            label.append(1)
        elif key[-2] == 'white':
            label.append(0)
        else:
            label.append(0)
        ip.append(key[3])
        max_cip_version = 0
        for tem in key[-11]:
            try:
                if int(tem) > max_cip_version:
                    max_cip_version = int(tem)
            except ValueError:
                max_cip_version = -1


        cipher_version.append(max_cip_version)
        subject_one = Find_first(key[53])
        issue_one = Find_first(key[54])
        cipher_one.append(max_cip_version)

        if key[63] != 0 :
            bitFre.append(key[65])
            entropy.append(key[66:70])
            cipher_bifFre.append(key[71])
            cipher_entropy.append(key[73:76])
            if key[-2] == 'black':
                label_e.append(1)
            else:
                label_e.append(0)

        subject.append(subject_one)
        issue.append(issue_one)

        cipher.append(cipher_one)


    ip_ans = oh_encoding(ip)
    subject_ans = oh_encoding(subject)
    issue_ans = oh_encoding(issue)

    cipher = np.hstack((cipher, subject_ans, issue_ans))

    mean_list = [8, 12, 16, 20, 23, 26, 29, 32]
    from sklearn.feature_selection import VarianceThreshold

    from sklearn.preprocessing import MinMaxScaler

    select = VarianceThreshold(threshold=0)
    dataset_flow = select.fit_transform(flow)
    minMax = MinMaxScaler()
    dataset_flow = minMax.fit_transform(dataset_flow)

    # dataset_mix = (np.hstack((flow, subject_ans, issue_ans, matrix)))
        # dataset_mix.append(list(dataset_flow[i]) + (list(issue_ans[i])) + list(subject_ans[i]))
    print("dataset is formed by {}".format(flag))
    ratio =  len(dataset_b)+ len(dataset_w)
    if flag == 'flow':
        return dataset_flow[:ratio], dataset_flow[ratio:], label[:ratio], label[ratio:]
    elif flag == 'subject':
        return subject_ans[:ratio], subject_ans[ratio:], label[:ratio], label[ratio:]
    elif flag == 'issue':
        return issue_ans[:ratio], issue_ans[ratio:], label[:ratio], label[ratio:]
    elif flag == 'matrix':
        return matrix[:ratio], matrix[ratio:], label[:ratio], label[ratio:]
    elif flag == 'payload':
        return payload[:ratio], payload[ratio:],  label[:ratio], label[ratio:]
    elif flag == 'time':
        return time[:ratio], time[ratio:], label[:ratio], label[ratio:]
    elif flag == 'cipher':
        return cipher[:ratio], cipher[ratio:], label[:ratio], label[ratio:]
    elif flag == 'flag':
        return tcp_flag[:ratio], tcp_flag[ratio:], label[:ratio], label[ratio:]
    elif flag == 'speed':
        return speed[:ratio], speed[ratio:], label[:ratio], label[ratio:]
    elif flag == 'bitFre':
        return bitFre, label_e
    elif flag == 'entropy':
        return entropy, label_e
    elif flag == 'cipher_entropy':
        return cipher_entropy, label_e
    elif flag == 'cipher_bitFre':
        return cipher_bifFre, label_e
    else:
        print("select wrong")



def main():
    pre_data('flow')

def pre_data_flow(flag):
    """
    将分割为流后的数据集进行一个数据预处理
    :param flag: 返回什么特征集合
    :return: 返回的特征集合
    """
    dataset_train_b = np.load("feature_flow/train_black.npy", allow_pickle=True)
    dataset_train_w = np.load("feature_flow/train_white.npy", allow_pickle=True)
    dataset_test_b = np.load("feature_flow/test_black.npy", allow_pickle=True)
    dataset_test_w = np.load("feature_flow/test_white.npy", allow_pickle=True)
    dataset_train = np.vstack((dataset_train_b ,dataset_train_w))
    dataset_test = np.vstack((dataset_test_b , dataset_test_w))
    dataset = np.vstack((dataset_train, dataset_test))

    # 前6000 训练集合，后4000测试集合
    ip = []
    subject = []
    issue = []
    cipher_version = []
    label = []
    matrix = []
    for key in dataset:
        if (key[-5] != 0):
            if key[-2] == 'black':
                label.append(0)
            elif key[-2] == 'white':
                label.append(1)
            else:
                label.append(1)
            ip.append(key[3])
            max_cip_version = 0
            # for tem in key[-11]:
            #     try:
            #         if int(tem) > max_cip_version:
            #             max_cip_version = int(tem)
            #     except ValueError:
            #         max_cip_version = -1
            cipher_version.append(max_cip_version)
            subject.append(Find_first(key[53]))
            issue.append(Find_first(key[54]))
            # print(key[-3].reshape(1,-1))
            # print(key[-3].flatten())
            matrix.append(key[-9].flatten())
    ip_ans = oh_encoding(ip)
    subject_ans = oh_encoding(subject)
    issue_ans = oh_encoding(issue)
    dataset_flow = []
    mean_list = [8, 12, 16, 20, 23, 26, 29, 32]
    from sklearn.feature_selection import VarianceThreshold
    for i in range(len(dataset)):
        feature = []
        if dataset[i][-5] != 0:
            for j in range(0, 3):
                feature.append(float(dataset[i][j]))
            for j in range(4, 51):
                feature.append(float(dataset[i][j]))
            # for j in range(4, 6):
            #     feature.append(float(dataset[i][j]))
            # for j in mean_list:
            #     feature.append(float(dataset[i][j]))
            feature.append(int(find_min((dataset[i][52]))))
            # certificate_time
            feature.append(find_self_signed((dataset[i][51])))
            # 自签名
            dataset_flow.append(feature)
    from sklearn.preprocessing import MinMaxScaler

    select = VarianceThreshold(threshold=0)
    dataset_flow = select.fit_transform(dataset_flow)
    minMax = MinMaxScaler()
    dataset_flow = minMax.fit_transform(dataset_flow)
    dataset_mix = (np.hstack((dataset_flow, subject_ans, issue_ans, matrix)))
    # dataset_mix.append(list(dataset_flow[i]) + (list(issue_ans[i])) + list(subject_ans[i]))
    print("dataset is formed by {}".format(flag))
    dataset_mix = select.fit_transform(dataset_mix)
    num = len(dataset_train_b) + len(dataset_train_w)
    if flag == 'flow':
        return dataset_flow[:num], dataset_flow[num:], label[:num], label[num:]
    elif flag == 'subject':
        return subject_ans[:num], subject_ans[num:], label[:num], label[num:]
    elif flag == 'issue':
        return issue_ans[:num], issue_ans[num:], label[:num], label[num:]
    elif flag == 'matrix':
        return matrix[:num], matrix[num:], label[:num], label[num:]
    elif flag == 'mix':
        return  dataset_mix[:num], dataset_mix[num:], label[:num], label[num:]
    else:
        print("select wrong")


    # return dataset_flow[:6000], dataset_flow[6000:], label[:6000], label[6000:]
    # return subject_ans[:6000],subject_ans[6000:], label[:6000], label[6000:]
    # return issue_ans[:6000], issue_ans[6000:], label[:6000], label[6000:]
    # return ip_ans[:6000], ip_ans[6000:], label[:6000], label[6000:]
    # return dataset_mix[:6000], dataset_mix[6000:], label[:6000], label[6000:]
def pre_data_1():
    dataset_b, dataset_w = data_read()
    dataset_train = dataset_b[:3000] + dataset_w[:3000]
    dataset_test = dataset_b[3000:] + dataset_w[3000:]
    dataset = dataset_train + dataset_test
    # 前6000 训练集合，后4000测试集合
    ip = []
    subject = []
    issue = []
    cipher_version = []
    label = []
    matrix = []
    for key in dataset:
        if key[-2] == 'black':
            label.append(1)
        elif key[-2] == 'white':
            label.append(0)
        else:
            label.append(0)
        ip.append(key[3])
        max_cip_version = 0
        for tem in list_string(key[-11]):
            try:
                if int(tem) > max_cip_version:
                    max_cip_version = int(tem)
            except ValueError:
                max_cip_version = -1
        cipher_version.append(max_cip_version)
        subject.append(find_first(list_string(key[53])))
        issue.append(find_first(list_string(key[54])))
        print(list_string(key[-3]))
        matrix.append(list_string(key[-3]))
    ip_ans = oh_encoding(ip)
    subject_ans = oh_encoding(subject)
    issue_ans = oh_encoding(issue)
    dataset_flow = []
    mean_list = [8, 12, 16, 20, 23, 26, 29, 32]
    from sklearn.feature_selection import VarianceThreshold
    for i in range(len(dataset)):
        feature = []
        for j in range(0, 3):
            feature.append(float(dataset[i][j]))
        for j in range(4, 51):
            feature.append(float(dataset[i][j]))
        # for j in range(4, 6):
        #     feature.append(float(dataset[i][j]))
        # for j in mean_list:
        #     feature.append(float(dataset[i][j]))
        feature.append(int(find_min(list_string(dataset[i][52]))))
        # certificate_time
        feature.append(find_self_signed(list_string(dataset[i][51])))
        # 自签名
        dataset_flow.append(feature)
    from sklearn.preprocessing import MinMaxScaler

    select = VarianceThreshold(threshold=0)
    dataset_flow = select.fit_transform(dataset_flow)
    minMax = MinMaxScaler()
    dataset_flow = minMax.fit_transform(dataset_flow)
    dataset_mix = []
    for i in range(len(dataset)):
        dataset_mix.append(np.hstack((dataset_flow[i], subject_ans[i])))
        # dataset_mix.append(list(dataset_flow[i]) + (list(issue_ans[i])) + list(subject_ans[i]))
    print("dataset is formed by {}".format("mixed"))
    dataset_mix = select.fit_transform(dataset_mix)
    # return dataset_flow[:6000], dataset_flow[6000:], label[:6000], label[6000:]
    # return subject_ans[:6000],subject_ans[6000:], label[:6000], label[6000:]
    # return issue_ans[:6000], issue_ans[6000:], label[:6000], label[6000:]
    # return ip_ans[:6000], ip_ans[6000:], label[:6000], label[6000:]
    # return dataset_mix[:6000], dataset_mix[6000:], label[:6000], label[6000:]

if __name__ == "__main__":
    # pre_data_beh('beh', 30, '')
    pre_data('flow', 'flow')