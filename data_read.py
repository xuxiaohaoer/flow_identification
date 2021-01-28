import json
from sklearn.preprocessing import MinMaxScaler
import csv
import os
import numpy as np
import pandas as pd
x_train = []
x_test = []
def data_read():
    minMax = MinMaxScaler()
    with open('feature_list_train.csv', 'r',) as f:
        reader = csv.reader(f)
        x_train = list(reader)
        # x_black = json.loads(tem)
        # x_black = minMax.fit_transform(json.loads(tem))
    f.close()
    with open('feature_list_test.csv', 'r') as f:
        reader = csv.reader(f)
        x_test = list(reader)
        # x_white = json.loads(tem)
        # x_white = minMax.fit_transform(json.loads(tem))
    f.close
    return x_train, x_test

def data_read1():
    basedir = "../../cicids2018/cicids2018/"
    data_b = []
    data_w = []
    for file in os.listdir(basedir):
        with open(basedir + file, 'r') as f:
            reader = csv.reader(f)
            lister = list(reader)
            for i,key in enumerate(lister):
                if key[0] == '443':
                    if key[-1] == 'Benign':
                        data_w.append(key)
                    else:
                        data_b.append(key)
        f.close()
    print(len(data_b), len(data_w))
    with open("feature_base/feature_b_2018.csv", 'w') as f:
        f_csv = csv.writer(f)
        for key in data_b:
            f_csv.writerow(key)
    f.close()
    with open("feature_base/feature_w_2018.csv", 'w') as f:
        f_csv = csv.writer(f)
        for key in data_w:
            f_csv.writerow(key)
    f.close()
    print('end')

def data_read2():
    print("begin")
    dataset_b = []
    dataset_w = []
    label = []
    with open("feature_base/feature_b_2018.csv", 'r') as f:
        f_csv = csv.reader(f)
        dataset_1 = list(f_csv)
        for key  in dataset_1:

            dataset_b.append(key[3:-1])
            label.append(1)
    f.close()
    with open("feature_base/feature_w_2018.csv", 'r') as f:
        f_csv = csv.reader(f)
        dataset_2 = list(f_csv)
        for key in dataset_2:
            key[np.isnan(key)] = 0

            dataset_w.append(key[3:-1])
            label.append(0)

    f.close()
    dataset = dataset_b + dataset_w
    print(len(dataset), len(label))
    return dataset, label

if __name__ == "__main__":
    data_read2()