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
x_train = []
y_train = []
x_test = []
# 自测
y_test = []
y_label = []
# X = []
# Y = []
print("begin system")
x_train, y_train, x_test, y_label = dataset.pre_data()

# lightGBM
# y_test = model.LightGBM(x_train, y_train, x_test, y_label)
# index.cal_index_1(y_test, y_label)
print("RandomFroest")
y_test = model.RandomForest(x_train, y_train, x_test)
index.cal_index(y_test, y_label)

# print("GradientBoosting")
# y_test = model.GradientBoosting(x_train, y_train, x_test)
# index.cal_index(y_test, y_label)
# f = open("result.txt", 'w')
# for i in range(len(x_test)):
#     str = x_name[i] + "," + y_test[i][0] + "\n"
#     f.write(str)
# f.close()
print("DS end")
