import pre
import numpy as np
from sklearn.model_selection import train_test_split
x_black = pre.pre_pcap("data/eta_1/train/black/")
x_white = pre.pre_pcap("data/eta_1/train/white/")
x_train = []
y_train = []
x_test = []
y_label = []


def predata():
    for sample in x_black[:1000]:
        x_train.append(sample)
        y_train.append("black")
    for sample in x_white[:1000]:
        x_train.append(sample)
        y_train.append("white")
    for sample in x_black[1000:]:
        x_test.append(sample)
        y_label.append(["black"])
    for sample in x_white[1000:]:
        x_test.append(sample)
        y_label.append(["white"])
    return(x_train, y_train, x_test, y_label)


def pre_data():
    X = []
    Y = []
    for sample in x_black:
        X.append(sample)
        Y.append("black")
    for sample in x_white:
        X.append(sample)
        Y.append("white")
    x_train, x_test, y_train, y_label = train_test_split(X, Y, test_size=0.33, random_state=42)
    print("pre_data end")
    return(x_train, y_train, x_test, y_label)


if __name__ =="__main__":
    pre_data()
