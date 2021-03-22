import pandas as pd
from datetime import datetime
from matplotlib import pyplot
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import mean_squared_error
from keras.models import Sequential
from keras.layers import Dense
from keras.layers import LSTM
from keras.layers import Dropout
from keras import optimizers
from numpy import concatenate
from math import sqrt
from pre_data import pre_data_beh
import numpy as np
# load data

from keras import regularizers



def series_to_supervised(data, n_in=1, n_out=1, dropnan=True):
    # convert series to supervised learning
    n_vars = 1 if type(data) is list else data.shape[1]
    df = pd.DataFrame(data)
    cols, names = list(), list()
    # input sequence (t-n, ... t-1)
    for i in range(n_in, 0, -1):
        cols.append(df.shift(i))
        names += [('var%d(t-%d)' % (j + 1, i)) for j in range(n_vars)]
    # forecast sequence (t, t+1, ... t+n)
    for i in range(0, n_out):
        cols.append(df.shift(-i))
        if i == 0:
            names += [('var%d(t)' % (j + 1)) for j in range(n_vars)]
        else:
            names += [('var%d(t+%d)' % (j + 1, i)) for j in range(n_vars)]
    # put it all together
    agg = pd.concat(cols, axis=1)
    agg.columns = names
    # drop rows with NaN values
    if dropnan:
        agg.dropna(inplace=True)
    return agg


# def cs_to_sl():
#     # load dataset
#     dataset = pd.read_csv('pollution.csv', header=0, index_col=0)
#     values = dataset.values
#     # integer encode direction
#     encoder = LabelEncoder()
#     values[:, 4] = encoder.fit_transform(values[:, 4])
#     # ensure all data is float
#     values = values.astype('float32')
#     # normalize features
#     scaler = MinMaxScaler(feature_range=(0, 1))
#     scaled = scaler.fit_transform(values)
#     # frame as supervised learning
#     reframed = series_to_supervised(scaled, 1, 1)
#     # drop columns we don't want to predict
#     reframed.drop(reframed.columns[[9, 10, 11, 12, 13, 14, 15]], axis=1, inplace=True)
#     print(reframed.head())
#     return reframed, scaler

#
# def train_test(reframed):
#     # split into train and test sets
#     values = reframed.values
#     n_train_hours = 365 * 24
#     train = values[:n_train_hours, :]
#     test = values[n_train_hours:, :]
#     # split into input and outputs
#     train_X, train_y = train[:, :-1], train[:, -1]
#     test_X, test_y = test[:, :-1], test[:, -1]
#     # reshape input to be 3D [samples, timesteps, features]
#     train_X = train_X.reshape((train_X.shape[0], 1, train_X.shape[1]))
#     test_X = test_X.reshape((test_X.shape[0], 1, test_X.shape[1]))
#     print(train_X.shape, train_y.shape, test_X.shape, test_y.shape)
#     return train_X, train_y, test_X, test_y


def fit_network(train_X, train_y, test_X, test_y):
    model = Sequential()
    model.add(LSTM(64, input_shape=(train_X.shape[1], train_X.shape[2]), kernel_regularizer=regularizers.l2(0.01)))
    model.add(Dropout(0.1))
    model.add(Dense(1, activation='sigmoid'))
    sgd = optimizers.SGD(lr=0.005, decay=1e-6, momentum=0.9, nesterov=True)
    # model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.compile(loss='binary_crossentropy', optimizer=sgd, metrics=['accuracy'])
    # model.add(Dense(1))
    # model.compile(loss='mae', optimizer='adam')
    # fit network
    # history = model.fit(train_X, train_y, epochs=200, batch_size=48, validation_data=(test_X, test_y), verbose=2,
    #                     shuffle=False)
    history = model.fit(train_X, train_y, epochs=100, batch_size=16, validation_split=0.2, verbose=2,
                        shuffle=True)
    # plot history
    pyplot.plot(history.history['loss'], label='train')
    pyplot.plot(history.history['val_loss'], label='test')
    pyplot.legend()
    pyplot.show()
    # make a prediction

    yhat = model.predict(test_X)
    scores = model.evaluate(test_X, test_y, verbose=0)

    print(scores)
    # test_X = test_X.reshape((test_X.shape[0], test_X.shape[2]))
    # # invert scaling for forecast
    # inv_yhat = concatenate((yhat, test_X[:, 1:]), axis=1)
    # # inv_yhat = scaler.inverse_transform(inv_yhat)
    # inv_yhat = inv_yhat[:, 0]
    # # invert scaling for actual
    # # inv_y = scaler.inverse_transform(test_X)
    # inv_y = test_y
    # # inv_y = inv_y[:, 0]
    # calculate RMSE
    # print(yhat)
    # print(inv_y)
    # print(inv_yhat)
    # rmse = sqrt(mean_squared_error(inv_y, inv_yhat))
    # print('Test RMSE: %.3f' % rmse)



if __name__ == '__main__':
    # drow_pollution()
    # reframed, scaler = cs_to_sl()
    # train_X, train_y, test_X, test_y = train_test(reframed)
    train_X,  test_X, train_y, test_y = pre_data_beh('mix_seq_dir', 35, '')
    train_X = np.array(train_X)
    train_y = np.array(train_y)
    test_X = np.array(test_X)
    test_y = np.array(test_y)

    train_X = train_X.reshape((train_X.shape[0], 1, train_X.shape[1]))
    print(train_X.shape)
    test_X = test_X.reshape((test_X.shape[0], 1, test_X.shape[1]))
    print(train_X.shape)
    fit_network(train_X, train_y, test_X, test_y)

