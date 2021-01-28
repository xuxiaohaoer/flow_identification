from sklearn.preprocessing import OneHotEncoder
import csv
import numpy as np
def data_read():
    dataset_b = np.load("feature_npy/feature_train_black.npy", allow_pickle=True)
    dataset_w = np.load("feature_npy/feature_train_white.npy", allow_pickle=True)
    dataset_t = np.load("feature_npy/feature_test.npy", allow_pickle=True)

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

def pre_data(flag):
    dataset_b, dataset_w, dataset_t= data_read()

    dataset = np.vstack((dataset_b,dataset_w, dataset_t))
    print(dataset.shape)
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
        for tem in key[-11]:
            try:
                if int(tem) > max_cip_version:
                    max_cip_version = int(tem)
            except ValueError:
                max_cip_version = -1
        cipher_version.append(max_cip_version)
        subject.append(Find_first(key[53]))
        issue.append(Find_first(key[54]))
        # print(key[-3].reshape(1,-1))
        # print(key[-3].flatten())
        matrix.append(key[-3].flatten())
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
    dataset_mix = []
    dataset_mix = (np.hstack((dataset_flow, subject_ans, issue_ans, matrix)))
        # dataset_mix.append(list(dataset_flow[i]) + (list(issue_ans[i])) + list(subject_ans[i]))
    print("dataset is formed by {}".format(flag))
    dataset_mix = select.fit_transform(dataset_mix)
    if flag == 'flow':
        return dataset_flow[:6000], dataset_flow[6000:], label[:6000], label[6000:]
    elif flag == 'subject':
        return subject_ans[:6000], subject_ans[6000:], label[:6000], label[6000:]
    elif flag == 'issue':
        return issue_ans[:6000], issue_ans[6000:], label[:6000], label[6000:]
    elif flag == 'matrix':
        return matrix[:6000], matrix[6000:], label[:6000], label[6000:]
    elif flag == 'mix':
        return  dataset_mix[:6000], dataset_mix[6000:], label[:6000], label[6000:]
    else:
        print("select wrong")


def pre_data_ae(flag):
    dataset_b, dataset_w, dataset_t= data_read()

    dataset = np.vstack((dataset_b,dataset_w, dataset_t))
    print(dataset.shape)
    # 前6000 训练集合，后4000测试集合
    ip = []
    subject = []
    issue = []
    cipher_version = []
    label = []
    matrix = []
    d_b, d_w = [], []
    for key  in dataset:
        if key[-2] == 'black':
            d_b.append(key)
        else:
            d_w.append(key)
    dataset = np.vstack((d_w, d_b))
    for key in dataset:
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
        subject.append(Find_first(key[53]))
        issue.append(Find_first(key[54]))
        # print(key[-3].reshape(1,-1))
        # print(key[-3].flatten())
        matrix.append(key[-3].flatten())
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
    dataset_mix = []
    dataset_mix = (np.hstack((dataset_flow, subject_ans, issue_ans, matrix)))
        # dataset_mix.append(list(dataset_flow[i]) + (list(issue_ans[i])) + list(subject_ans[i]))
    print("dataset is formed by {}".format(flag))
    dataset_mix = select.fit_transform(dataset_mix)

    if flag == 'flow':
        return dataset_flow[:4000], dataset_flow[4000:], label[:4000], label[4000:]
    elif flag == 'subject':
        return subject_ans[:4000], subject_ans[4000:], label[:4000], label[4000:]
    elif flag == 'issue':
        return issue_ans[:4000], issue_ans[4000:], label[:4000], label[4000:]
    elif flag == 'matrix':
        return matrix[:4000], matrix[4000:], label[:4000], label[4000:]
    elif flag == 'mix':
        return  dataset_mix[:4000], dataset_mix[4000:], label[:4000], label[4000:]
    else:
        print("select wrong")
def main():
    pre_data('flow')


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
    main()