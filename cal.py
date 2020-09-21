import  numpy as np
from cipher_suite import cipher_suites
from cipher_suite import index
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
    num = num // 8
    if num % 2 == 1:
        return True
    else:
        return False


def cal_urg(num):
    num = num // 32
    if num % 2 == 1:
        return True
    else:
        return False

def cal_matrix(seq):
    a = np.zeros((15, 15), dtype=int)
    for i, key in enumerate(seq):

        if i < len(seq)-1:
            a[key//150][seq[i+1]//150] += 1
    sum = np.sum(a)
    a = a/sum
    return a