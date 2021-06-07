from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import f1_score
def cal_index_sk(y_pred, y_label):
    print("acc:{}".format(accuracy_score(y_label, y_pred )))
    print("pre:{}".format(precision_score(y_label, y_pred, )))
    print("rec:{}".format(recall_score(y_label, y_pred)))
    print(confusion_matrix(y_label, y_pred, labels=[1,0]))
    matrix = confusion_matrix(y_label,y_pred, labels=[1,0])
    b_w = 0
    b_b = 0
    for i in range(len(y_label)):
        if y_label[i] == 1:
            if y_pred[i] == 1:
                b_b += 1
            else:
                b_w += 1
    acc = accuracy_score(y_label, y_pred )
    print("grade:{}".format(acc - matrix[0][1]/sum(matrix[0])))
    return (acc - matrix[0][1]/sum(matrix[0]))


def cal_acc_pre_rec(y_pred, y_label):
    print(confusion_matrix(y_label, y_pred, labels=[1, 0]))
    acc = round(accuracy_score(y_label, y_pred), 4)
    pre = round(precision_score(y_label, y_pred),4)
    rec = round(recall_score(y_label, y_pred),4)
    f1 = round(f1_score(y_label, y_pred),4)
    return acc,pre, rec, f1


def cal_index(y_test, y_label):
    acc = 0
    n = len(y_test)
    TP = 0
    FN = 0
    FP = 0
    TN = 0
    for i in range(n):
        if y_label[i] == "black":
            if y_test[i] == "black":
                TP += 1
            if y_test[i] == "white":
                FN += 1
        else:
            if y_test[i] == "black":
                FP += 1
            if y_test[i] == "white":
                TN += 1
        if y_test[i] == y_label[i]:
            acc += 1
    check_out = TP/(FN+TP)
    false_positive = FP/(FP+TN)
    grade = check_out - false_positive
    grade *= 100
    Acc = (TN + TP) / (TN + FP + TP + FN)
    Pre = TP / (FP + TP)
    Rec = TP / (TP + FN)
    Fpr = FP / (TN + FP)
    print("grade:", grade)
    acc = acc / n
    print("TT:", TP, "TF:", FN, "FT:", FP, "FF:", TN)
    print("Acc:", Acc, "Pre", Pre, "Rec", Rec, "Fdr:", Fpr)
    # print(accuracy_score(y_label, y_test))
    # print(precision_score(y_label, y_test))
    # print(recall_score(y_label, y_test))
    print("acc:", acc)


def cal_index_1(y_test, y_label):
    acc = 0
    n = len(y_test)
    TP = 0
    FN = 0
    FP = 0
    TN = 0
    for i in range(n):
        if y_label[i] == 1:
            if y_test[i] == 1:
                TP += 1
            if y_test[i] == 0:
                FN += 1
        else:
            if y_test[i] == 1:
                FP += 1
            if y_test[i] == 0:
                TN += 1
        if y_test[i] == y_label[i]:
            acc += 1
    check_out = TP/(FN+TP)
    false_positive = FP/(FP+TN)
    grade = check_out - false_positive
    grade *= 100

    print("grade:", grade)
    acc = acc / n
    print("acc:", acc)

    print("index end")


def Cal_ClusterIndex(y_label, y_pred):
    print("rand_socore:{}".format(metrics.adjusted_rand_score(y_label, y_pred)))
    print("mutual_info_score:{}".format(metrics.adjusted_mutual_info_score(y_label, y_pred)))
    print("fowlkes_mallows_score:{}".format(metrics.fowlkes_mallows_score(y_label, y_pred)))
    print("v-measure_score:{}".format(metrics.v_measure_score(y_label, y_pred)))
    print("homogeneity_score:{}".format(metrics.homogeneity_score(y_label, y_pred)))
    print("completeness_score:{}".format(metrics.completeness_score(y_label, y_pred)))