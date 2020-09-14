from sklearn.metrics import accuracy_score
from sklearn.metrics import precision_score
from sklearn.metrics import recall_score
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