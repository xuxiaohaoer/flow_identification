from sklearn.datasets import load_iris
from sklearn.model_selection import KFold, train_test_split
import model
import index
# from data_read import data_read
from sklearn.preprocessing import MinMaxScaler
from pre_data import pre_data
from pre_data import pre_data_beh
from pre_data import pre_data_flow
from pre_data import pre_data_test
from pre_data import pre_data_payload
def main():

    print("begin system")
    # 导入测试集和训练集
    # features = ['cipher', 'flow', 'subject', 'issue', 'matrix' ,'mix']
    # features = ['subject']
    # features = ['behavior', 'payload', 'direction']
    # features = ['mix_seq_dir', 'mix_seq', 'mix_seq_dir_1', 'matrix']
    # features = ['mix_seq_dir_1', 'mix_seq_1']
    features = ['payload']
    # features =  [i for i in range(100,1400, 100)]
    print(features)

    for feature in features:
        acc = []
        pre = []
        rec = []
        print("this is made by {}".format(feature))
        for length in range(10,80,5):
            x_train, x_test, y_train, y_label = pre_data_beh(feature, length, '')
            x = x_train + x_test
            y = y_train + y_label
            x_train, x_test, y_train, y_label = train_test_split(x,y, test_size=0.4, random_state=43)
            y_pred = model.RandomForest(x_train, y_train, x_test, 'tuning')
            acc_tem, pre_tem, rec_tem = index.cal_acc_pre_rec(y_pred, y_label)
            acc.append(acc_tem)
            pre.append(pre_tem)
            rec.append(rec_tem)
            print(acc_tem)
            print(pre_tem)
            print(rec_tem)


        print(acc)
        print(pre)
        print(rec)
        print("the result:", max(acc), acc.index(max(acc)))

        # print("GradientBoosting")
        # y_pred = model.GradientBoosting(x_train, y_train, x_test, 'tuning')
        # grad_tem = index.cal_index_sk(y_pred, y_label)
        # if grad < grad_tem:
        #     grad = grad_tem
        #     y_tem = y_pred
        # print("Voting")
        # y_pred = model.Voting(x_train, y_train, x_test)
        # grad_tem = index.cal_index_sk(y_pred, y_label)
        # if grad < grad_tem:
        #     grad = grad_tem
        #     y_tem = y_pred
    #     Y.append(y_tem)
    # print("###end result ###X")
    # index.cal_index_sk(cal_voting(Y), y_label)
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