# ! -*- coding: utf-8 -*-

'''
基于cicids2017数据集的基础自编码器和稀疏自编码器的实现
'''

import numpy as np
import matplotlib.pyplot as plt
from keras import regularizers
from scipy.stats import norm
import keras
# from tensorflow.keras.layers import Input, Dense, Lambda
# # from tensorflow.keras.optimizers import Adadelta
# # from tensorflow.keras.models import Model
# # from tensorflow.keras import backend as K
# # from tensorflow.keras.optimizers import RMSprop, Adam
from keras.layers import Input, Dense, Lambda
from keras.optimizers import Adadelta
from keras.models import Model
from keras import backend as K
from keras.optimizers import RMSprop, Adam

from keras.datasets import mnist
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.cluster import KMeans
import tensorflow as tf
import time
import os
import seaborn as sns
from pre_data import pre_data_ae

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 屏蔽通知信息和警告信息
#
dataset_path = '../dataset/'
saved_model_path = './saved_model/'
batch_size = 128
original_dim = 23
epochs = 30
# tf.debugging.set_log_device_placement(True)
# 加载数据集
# bf = pd.read_csv(dataset_path + 'benign2017data.csv')
# mf = pd.read_csv(dataset_path + 'malware2017data.csv')
# train_data, val_data = train_test_split(bf, test_size=len(mf) / len(bf), random_state=1)
# val_data_all = pd.concat([mf, val_data])
# # _, val_data = train_test_split(val_data_all,test_size=0.3,random_state=2)
# train_data, val_data, val_labels = [train_data.iloc[:, :original_dim].values, val_data_all.iloc[:, :original_dim].values, val_data_all.iloc[:,original_dim].values]
# print(train_data.shape)
# print(val_data.shape)
# print(val_labels)
train_data, train_label, val_data, val_label = pre_data_ae('flow')
# binary_labels =[]
# for label in val_labels:
#     if label != 'BENIGN':
#         binary_labels.append('MALWARE')
#     else:
#         binary_labels.append('BENIGN')
# binary_labels = np.array(binary_labels)

input_img = Input(shape=(original_dim,))
encoded = Dense(64, activation='relu')(input_img)
encoded = Dense(50, activation='relu')(encoded)
encoded = Dense(32, activity_regularizer=regularizers.l1(10e-5), activation='relu')(encoded)

decoded = Dense(50, activation='relu')(encoded)
decoded = Dense(64, activation='relu')(decoded)
decoded = Dense(original_dim, activation='sigmoid')(decoded)

op = Adadelta(learning_rate=0.0001)
autoencoder = Model(inputs=input_img, outputs=decoded)
autoencoder.compile(optimizer=op, loss='binary_crossentropy')

history = autoencoder.fit(train_data, train_data,
                nb_epoch=100,
                batch_size=256,
                shuffle=True,
                validation_data=(val_data, val_data))

# print(history.history.keys())
# plt.plot(history.history['loss'])
# plt.plot(history.history['val_loss'])
# plt.title('model loss')
# plt.ylabel('loss')
# plt.xlabel('epoch')
# plt.legend(['train', 'test'], loc='upper left')
# plt.show()

# autoencoder.load_weights(saved_model_path+'ae_reg_epoch')
pre_data = autoencoder.predict(val_data)
val_losses1 = tf.losses.binary_crossentropy(val_data, pre_data)
val_losses2 = tf.losses.mean_squared_error(val_data, pre_data)
val_df = pd.DataFrame({'binary_crossentropy':val_losses1,'mean_squared_error':val_losses2,'val_labels':val_labels})
labels = np.unique(val_labels)
i = 1
plt.rcParams['savefig.dpi'] = 300 #图片像素
plt.rcParams['figure.dpi'] = 300 #分辨率
for label in labels:
    loss = val_df['binary_crossentropy'][val_df['val_labels']==label]
    x = [i for i in range(len(loss)) ]
    plt.subplot(2,2,i)
    plt.scatter(x=np.array(x), y=np.array(loss), marker='.',c='r')
    plt.title(label)
    if i==4:
        plt.show()
        i=1
    else:
        i = i+1
plt.show()