from sklearn.datasets import load_iris
from sklearn.model_selection import KFold
from sklearn.preprocessing import OneHotEncoder
# import tensorflow as tf
import pre
import dataset
import model
import os
import random
import index
from data_read import data_read
from sklearn.preprocessing import MinMaxScaler
x_train = []
y_train = []
x_test = []
# 自测
y_test = []
y_label = []
# X = []
# Y = []
print("begin system")
x_1, x_2 = data_read()
print(len(x_1), len(x_2))
for key in x_1:
    x_train.append(key[:-18])
    y_train.append(key[-2])
for key in x_2:
    x_test.append(key[:-18])
    y_label.append(key[-2])
for i, key in enumerate(x_test):
    for j, num in enumerate(key):
        x_test[i][j] = float(num)
for i, key in enumerate(x_train):
    for j, num in enumerate(key):
        x_train[i][j] = float(num)
minMax = MinMaxScaler()
x_test = x_test + x_train
x_test = minMax.fit_transform(x_test)
x_train = x_test[4000:]
x_test = x_test[:4000]
# lightGBM
# y_test = model.LightGBM(x_train, y_train, x_test, y_label)
# index.cal_index_1(y_test, y_label)
print("RandomFroest")
y_test = model.RandomForest(x_train, y_train, x_test)
index.cal_index(y_test, y_label)

print("GradientBoosting")
y_test = model.GradientBoosting(x_train, y_train, x_test)
index.cal_index(y_test, y_label)

print("Voting")
y_test = model.Voting(x_train, y_train, x_test)
index.cal_index(y_test, y_label)
# f = open("result.txt", 'w')
# for i in range(len(x_test)):
#     str = x_name[i] + "," + y_test[i][0] + "\n"
#     f.write(str)
# f.close()
print("DS end")
