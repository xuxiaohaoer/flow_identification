from sklearn.datasets import load_iris
from sklearn.model_selection import KFold, train_test_split
import model
import index
from data_read import data_read
from sklearn.preprocessing import MinMaxScaler


def main():
    x_train = []
    y_train = []
    x_test = []
    # 自测
    y_pred = []
    y_label = []
    print("begin system")
    x_1, x_2 = data_read()
    print(len(x_1), len(x_2))
    # 导入测试集和训练集
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
    X = x_test + x_train
    Y = y_label + y_train
    X = minMax.fit_transform(X)
    # x_train = X[4000:]
    # x_test = X[:4000]
    # X = x_train
    # Y = y_train
    # X = minMax.fit_transform(X)
    x_train, x_test, y_train, y_label = train_test_split(X, Y, test_size=0.4, random_state=42)

    # lightGBM
    # y_pred = model.LightGBM(x_train, y_train, x_test, y_label)
    # index.cal_index_1(y_pred, y_label)'
    print("kmeans")
    y_pred = model.cluster(x_train, y_train, x_test)
    from sklearn import metrics
    print("grade:{}".format(metrics.adjusted_rand_score(y_label, y_pred)))
    print(metrics.adjusted_mutual_info_score(y_label, y_pred))
    print(metrics.fowlkes_mallows_score(y_label, y_pred))
    print("v-measure:{}".format(metrics.v_measure_score(y_label, y_pred)))
    # print("RandomFroest")
    # y_pred = model.RandomForest(x_train, y_train, x_test)
    # index.cal_index(y_pred, y_label)
    #
    # print("GradientBoosting")
    # y_pred = model.GradientBoosting(x_train, y_train, x_test)
    # index.cal_index(y_pred, y_label)
    #
    # print("Voting")
    # y_pred = model.Voting(x_train, y_train, x_test)
    # index.cal_index(y_pred, y_label)
    #
    # print("DS end")
if __name__ == "__main__":
    main()