# -*- coding: utf-8 -*-
"""
Created on Wed Jul 25 22:18:47 2018

@author: 24630
"""

# 回归问题示例


import tensorflow as tf
import numpy as np
import matplotlib.pyplot as plt

BATCH_START = 0  # 建立 batch data 时候的 index
TIME_STEPS = 20  # backpropagation through time 的time_steps
BATCH_SIZE = 50
INPUT_SIZE = 1  # x数据输入size
OUTPUT_SIZE = 2  # cos数据输出 size  代表0 - 1分别的概率
CELL_SIZE = 10  # RNN的 hidden unit size
LR = 0.006  # learning rate


# 定义一个生成数据的 get_batch function:
def get_batch():
    # global BATCH_START, TIME_STEPS
    # xs shape (50batch, 20steps)
    xs = np.arange(BATCH_START, BATCH_START + TIME_STEPS * BATCH_SIZE).reshape((BATCH_SIZE, TIME_STEPS)) / (200 * np.pi)
    res = np.where(np.cos(4 * xs) >= 0, 0, 1).tolist()
    for i in range(BATCH_SIZE):
        for j in range(TIME_STEPS):
            res[i][j] = [0, 1] if res[i][j] == 1 else [1, 0]
    # returned  xs and res: shape (batch, step, input/output)
    return [xs[:, :, np.newaxis], np.array(res)]


# 定义 LSTMRNN 的主体结构
class LSTMRNN(object):
    def __init__(self, n_steps, input_size, output_size, cell_size, batch_size):
        self.n_steps = n_steps
        self.input_size = input_size
        self.output_size = output_size
        self.cell_size = cell_size
        self.batch_size = batch_size
        with tf.name_scope('inputs'):
            self.xs = tf.placeholder(tf.float32, [None, n_steps, input_size], name='xs')
            self.ys = tf.placeholder(tf.float32, [None, n_steps, output_size], name='ys')
        with tf.variable_scope('in_hidden'):
            self.add_input_layer()
        with tf.variable_scope('LSTM_cell'):
            self.add_cell()
        with tf.variable_scope('out_hidden'):
            self.add_output_layer()
        with tf.name_scope('cost'):
            self.compute_cost()
        with tf.name_scope('train'):
            self.train_op = tf.train.AdamOptimizer(LR).minimize(self.cost)

    # 设置 add_input_layer 功能, 添加 input_layer:
    def add_input_layer(self, ):
        l_in_x = tf.reshape(self.xs, [-1, self.input_size], name='2_2D')  # (batch*n_step, in_size)
        # Ws (in_size, cell_size)
        Ws_in = self._weight_variable([self.input_size, self.cell_size])
        # bs (cell_size, )
        bs_in = self._bias_variable([self.cell_size, ])
        # l_in_y = (batch * n_steps, cell_size)
        with tf.name_scope('Wx_plus_b'):
            l_in_y = tf.matmul(l_in_x, Ws_in) + bs_in
        # reshape l_in_y ==> (batch, n_steps, cell_size)
        self.l_in_y = tf.reshape(l_in_y, [-1, self.n_steps, self.cell_size], name='2_3D')

    # 设置 add_cell 功能, 添加 cell, 注意这里的 self.cell_init_state,
    #  因为我们在 training 的时候, 这个地方要特别说明.
    def add_cell(self):
        lstm_cell = tf.contrib.rnn.BasicLSTMCell(self.cell_size, forget_bias=1.0, state_is_tuple=True)
        lstm_cell = tf.contrib.rnn.MultiRNNCell([lstm_cell], 1)
        with tf.name_scope('initial_state'):
            self.cell_init_state = lstm_cell.zero_state(self.batch_size, dtype=tf.float32)
        self.cell_outputs, self.cell_final_state = tf.nn.dynamic_rnn(lstm_cell,
                                                                     self.l_in_y,
                                                                     initial_state=self.cell_init_state,
                                                                     time_major=False)

    # 设置 add_output_layer 功能, 添加 output_layer:
    def add_output_layer(self):
        # shape = (batch * steps, cell_size)
        l_out_x = tf.reshape(self.cell_outputs, [-1, self.cell_size], name='2_2D')
        Ws_out = self._weight_variable([self.cell_size, self.output_size])
        bs_out = self._bias_variable([self.output_size, ])
        # shape = (batch * steps, output_size)
        with tf.name_scope('Wx_plus_b'):
            self.pred = tf.matmul(l_out_x, Ws_out) + bs_out

    # 添加 RNN 中剩下的部分:
    def compute_cost(self):
        self.cost = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits(labels=self.ys, logits=self.pred))

    def ms_error(self, labels, logits):
        return tf.square(tf.subtract(labels, logits))

    def _weight_variable(self, shape, name='weights'):
        initializer = tf.random_normal_initializer(mean=0., stddev=1., )
        return tf.get_variable(shape=shape, initializer=initializer, name=name)

    def _bias_variable(self, shape, name='biases'):
        initializer = tf.constant_initializer(0.1)
        return tf.get_variable(name=name, shape=shape, initializer=initializer)


# 训练 LSTMRNN
if __name__ == '__main__':

    # 搭建 LSTMRNN 模型
    model = LSTMRNN(TIME_STEPS, INPUT_SIZE, OUTPUT_SIZE, CELL_SIZE, BATCH_SIZE)
    sess = tf.Session()
    saver = tf.train.Saver(max_to_keep=3)
    sess.run(tf.global_variables_initializer())
    t = 0
    if (t == 1):
        model_file = tf.train.latest_checkpoint('model/')
        saver.restore(sess, model_file)
        xs, res = get_batch()  # 提取 batch data
        feed_dict = {model.xs: xs}
        pred = sess.run(model.pred, feed_dict=feed_dict)
        #        xs.shape = (-1,1)
        #        res.shape = (-1, 1)
        #        pred.shape = (-1, 1)
        res = np.argmax(res, axis=2)
        pred = np.argmax(pred, axis=1)
        xs = xs.reshape(-1, 1)
        res = res.reshape(-1, 1)
        pred = pred.reshape(-1, 1)
        print(xs.shape, res.shape, pred.shape)
        plt.figure()
        plt.plot(xs, res, '-r')
        plt.plot(xs, pred, '--g')
        plt.show()
    else:
        # matplotlib可视化
        plt.ion()  # 设置连续 plot
        plt.show()
        # 训练多次
        for i in range(1500):
            xs, res = get_batch()  # 提取 batch data
            # print(res.shape)
            # 初始化 data
            feed_dict = {
                model.xs: xs,
                model.ys: res,
            }
            print(xs[0])
            print(res[0])
            # 训练
            _, cost, state, pred = sess.run(
                [model.train_op, model.cost, model.cell_final_state, model.pred],
                feed_dict=feed_dict)

            # plotting
            res = np.argmax(res, axis=2)
            pred = np.argmax(pred, axis=1)
            x = xs.reshape(-1, 1)
            r = res.reshape(-1, 1)
            p = pred.reshape(-1, 1)

            plt.clf()
            plt.plot(x, r, 'r', x, p, 'b--')
            plt.ylim((-1.2, 1.2))
            plt.draw()
            plt.pause(0.3)  # 每 0.3 s 刷新一次

            # 打印 cost 结果
            if i % 20 == 0:
                saver.save(sess, "model/lstem_text.ckpt", global_step=i)  #
                print('cost: ', round(cost, 4))
    print("end")









