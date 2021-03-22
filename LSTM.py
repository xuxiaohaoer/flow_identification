import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import tensorflow as tf
from keras.layers import LSTM
import pre_data
# 定义常量
rnn_unit = 10  # hidden layer units
input_size = 35
output_size = 1
lr = 0.0006  # 学习率
# ——————————————————导入数据——————————————————————
# f = open('dataset_2.csv')
# df = pd.read_csv(f)  # 读入股票数据
# data = df.iloc[:, 2:10].values  # 取第3-10列
x_train, x_test, y_train, y_label = pre_data.pre_data_beh('mix_seq_dir', 35, '')
X1, X2 = [], []
for i in range(len(x_train)):
    X1.append(np.hstack((x_train[i], y_train[i])))
for i in range(len(x_test)):
    X2.append(np.hstack((x_test[i], y_label[i])))
data = np.vstack((X1,X2))


# 获取训练集
def get_train_data(batch_size=60, time_step=20, train_begin=0, train_end=6000):
    batch_index = []
    print(len(data))
    print(train_begin)
    print(train_end)
    data_train = data[train_begin:train_end]
    print("data_train:", len(data_train))
    normalized_train_data = (data_train - np.mean(data_train, axis=0)) / np.std(data_train, axis=0)  # 标准化
    train_x, train_y = [], []  # 训练集

    for i in range(len(normalized_train_data) - time_step):
        if i % batch_size == 0:
            batch_index.append(i)
        # x = normalized_train_data[i:i + time_step, :7]
        # y = normalized_train_data[i:i + time_step, 7, np.newaxis]
        x = data_train[i:i + time_step, :35]
        y = data_train[i:i + time_step, 35, np.newaxis]
        train_x.append(x.tolist())
        train_y.append(y.tolist())
    batch_index.append((len(normalized_train_data) - time_step))
    print(len(train_x[0]))
    print(train_y[0])
    print("batch_index:", batch_index)
    return batch_index, train_x, train_y


# 获取测试集
def get_test_data(time_step=20, test_begin=6000):
    data_test = data[test_begin:]
    mean = np.mean(data_test, axis=0)
    std = np.std(data_test, axis=0)
    normalized_test_data = (data_test - mean) / std  # 标准化
    size = (len(normalized_test_data) + time_step - 1) // time_step  # 有size个sample
    test_x, test_y = [], []
    for i in range(size - 1):
        # x = normalized_test_data[i * time_step:(i + 1) * time_step, :7]
        # y = normalized_test_data[i * time_step:(i + 1) * time_step, 7]
        x = data_test[i:i + time_step, :35]
        y = data_test[i:i + time_step, 35, np.newaxis]
        test_x.append(x.tolist())
        test_y.extend(y)
    test_x.append((normalized_test_data[(i + 1) * time_step:, :7]).tolist())
    test_y.extend((normalized_test_data[(i + 1) * time_step:, 7]).tolist())
    return mean, std, test_x, test_y


# ——————————————————定义神经网络变量——————————————————
# 输入层、输出层权重、偏置

weights = {
    'in': tf.Variable(tf.random_normal([input_size, rnn_unit])),
    'out': tf.Variable(tf.random_normal([rnn_unit, 1]))
}
biases = {
    'in': tf.Variable(tf.constant(0.1, shape=[rnn_unit, ])),
    'out': tf.Variable(tf.constant(0.1, shape=[1, ]))
}


# ——————————————————定义神经网络变量——————————————————
def lstm(X):
    batch_size = tf.shape(X)[0]
    time_step = tf.shape(X)[1]
    w_in = weights['in']
    b_in = biases['in']
    input = tf.reshape(X, [-1, input_size])  # 需要将tensor转成2维进行计算，计算后的结果作为隐藏层的输入
    input_rnn = tf.matmul(input, w_in) + b_in
    input_rnn = tf.reshape(input_rnn, [-1, time_step, rnn_unit])  # 将tensor转成3维，作为lstm cell的输入
    with tf.variable_scope('cell_def'):
        cell = tf.nn.rnn_cell.BasicLSTMCell(rnn_unit)
    init_state = cell.zero_state(batch_size, dtype=tf.float32)
    # tf.reset_default_graph()
    with tf.variable_scope('rnn_def'):
        output_rnn, final_states = tf.nn.dynamic_rnn(cell, input_rnn, initial_state=init_state, dtype=tf.float32)  # output_rnn是记录lstm每个输出节点的结果，final_states是最后一个cell的结果
    output = tf.reshape(output_rnn, [-1, rnn_unit])  # 作为输出层的输入
    w_out = weights['out']
    b_out = biases['out']
    pred = tf.matmul(output, w_out) + b_out
    return pred, final_states


# ——————————————————训练模型——————————————————
def train_lstm(batch_size=80, time_step=15, train_begin=0, train_end=6000):
    X = tf.placeholder(tf.float32, shape=[None, time_step, input_size])
    Y = tf.placeholder(tf.float32, shape=[None, time_step, output_size])
    # 训练样本中第2001 - 5785个样本，每次取15个
    batch_index, train_x, train_y = get_train_data(batch_size, time_step, train_begin, train_end)
    print(np.array(train_x).shape)  # 3785  15  7
    print(batch_index)
    # 相当于总共3785句话，每句话15个字，每个字7个特征（embadding）,对于这些样本每次训练80句话
    pred, _ = lstm(X)
    # 损失函数
    loss = tf.reduce_mean(tf.square(tf.reshape(pred, [-1]) - tf.reshape(Y, [-1])))
    train_op = tf.train.AdamOptimizer(lr).minimize(loss)
    saver = tf.train.Saver(tf.global_variables(), max_to_keep=15)
    with tf.Session() as sess:
        sess.run(tf.global_variables_initializer())
        # 重复训练200次
        for i in range(200):
            # 每次进行训练的时候，每个batch训练batch_size个样本
            for step in range(len(batch_index) - 1):
                _, loss_ = sess.run([train_op, loss], feed_dict={X: train_x[batch_index[step]:batch_index[step + 1]],
                                                                 Y: train_y[batch_index[step]:batch_index[step + 1]]})
            print(i, loss_)
            if i % 200 == 0:
                print("保存模型：", saver.save(sess, 'model/stock2.model', global_step=i))


train_lstm()


# ————————————————预测模型————————————————————
def prediction(time_step=20):
    X = tf.placeholder(tf.float32, shape=[None, time_step, input_size])
    mean, std, test_x, test_y = get_test_data(time_step)
    pred, _ = lstm(X)
    saver = tf.train.Saver(tf.global_variables())
    with tf.Session() as sess:
        # 参数恢复
        module_file = tf.train.latest_checkpoint('model')
        saver.restore(sess, module_file)
        test_predict = []
        for step in range(len(test_x) - 1):
            prob = sess.run(pred, feed_dict={X: [test_x[step]]})
            predict = prob.reshape((-1))
            test_predict.extend(predict)
        test_y = np.array(test_y) * std[7] + mean[7]
        test_predict = np.array(test_predict) * std[7] + mean[7]
        acc = np.average(np.abs(test_predict - test_y[:len(test_predict)]) / test_y[:len(test_predict)])  # 偏差
        print(test_predict)
        print(acc)
        # 以折线图表示结果
        plt.figure()
        plt.plot(list(range(len(test_predict))), test_predict, color='b')
        plt.plot(list(range(len(test_y))), test_y, color='r')
        plt.show()


prediction()