import pre
import _json
import json
import numpy as np
import csv
print("data_product begin")
x_black = pre.pre_pcap("data/eta/datacon_eta/train/black/", "black")
x_white = pre.pre_pcap("data/eta/datacon_eta/train/white/", "white")
x = x_black + x_white
with open("feature_list_train.csv", 'w+', newline='') as f:
    f_csv = csv.writer(f)
    for key in x:
        f_csv.writerow(key)
f.close()
print("train datasets end")
print(len(x))
x_test = pre.pre_pcap("data/eta/datacon_eta/test/", "")
with open("data/eta/datacon_eta/test_label/black.txt", 'r') as f:
    black = f.readlines()
    black = [i.replace("\n", '') for i in black]
with open("data/eta/datacon_eta/test_label/white.txt", 'r') as f:
    white = f.readlines()
    white = [i.replace("\n", "") for i in white]
print(len(x_test))
print("test datasets end")
with open("feature_list_test.csv", 'w+', newline='') as f:
    f_csv = csv.writer(f)
    for key in x_test:
        if key[-1] in black:
            key[-2] = 'black'
        if key[-1] in white:
            key[-2] = 'white'
        f_csv.writerow(key)
f.close()
print("data_product end")




