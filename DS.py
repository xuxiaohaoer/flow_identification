from sklearn.datasets import load_iris
from sklearn.model_selection import KFold, train_test_split
import model
import index
# from data_read import data_read
from sklearn.preprocessing import MinMaxScaler
from pre_data import pre_data

def main():

    print("begin system")
    # 导入测试集和训练集
    features = ['flow', 'subject', 'issue', 'matrix']
    features = ['subject']
    Y = []
    for feature in features:
        x_train, x_test, y_train, y_label = pre_data(feature)
        grad = 0
        y_tem = []

    # lightGBM
    # print("light GBM")
    # y_pred = model.LightGBM(x_train, y_train, x_test, y_label)
    # index.cal_index_1(y_pred, y_label)
    # print("kmeans")
    #
    # y_pred = model.KmeansCluster(X)
    # from sklearn import metrics
    # index.Cal_ClusterIndex(Y, y_pred)
    # print("DbsanCluster")
    # y_pred = model.DbscanCluster(x_train, x_test)
    # index.Cal_ClusterIndex(y_label, y_pred)
    #     print("RandomFroest")
    #     y_pred = model.RandomForest(x_train, y_train, x_test)
    #     grad_tem = index.cal_index_sk(y_pred, y_label)
    #     if grad < grad_tem:
    #         grad = grad_tem
    #         y_tem = y_pred
    #
    #     print("GradientBoosting")
    #     y_pred = model.GradientBoosting(x_train, y_train, x_test)
    #     grad_tem = index.cal_index_sk(y_pred, y_label)
    #     if grad < grad_tem:
    #         grad = grad_tem
    #         y_tem = y_pred
        print("Voting")
        y_pred = model.Voting(x_train, y_train, x_test)
        grad_tem = index.cal_index_sk(y_pred, y_label)
        if grad < grad_tem:
            grad = grad_tem
            y_tem = y_pred
        Y.append(y_tem)
    print("###end result ###X")
    index.cal_index_sk(cal_voting(Y), y_label)
    #
    # print("DS end")

def cal_voting(tem):
    result = []
    for i in range(len(tem[0])):
        black = 0
        white = 0
        for key in tem:
            if key[i] == 0:
                black += 1
            elif key[i] == 1:
                white +=1
        if black == white:
            if tem[0][i] == 0:
                black += 1
            elif tem[0][i] == 1:
                white += 1
        if black > white:
            result.append(0)
        else:
            result.append(1)
    return result




if __name__ == "__main__":
    main()