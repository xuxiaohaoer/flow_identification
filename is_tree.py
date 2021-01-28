from pre_data import pre_data
from pyod.models.iforest import IForest
from pyod.models.knn import KNN
from sklearn.model_selection import train_test_split
from pyod.utils.data import evaluate_print
import numpy as np


def main():
    dataset,label = pre_data()
    from numpy import nan as NA
    from sklearn.impute import SimpleImputer
    imputer = SimpleImputer(missing_values=NA, strategy="mean")
    dataset = imputer.fit_transform(dataset)
    x_train, x_test, y_train, y_label = train_test_split(dataset, label, test_size=0.3, random_state=44)
    # x_train, x_test, y_train, y_label =[], [], [], []
    # for i in range(1000):
    #     x_train.append(dataset[i])
    #     y_train.append(label[i])
    # for i in range(6000,10000):
    #     x_train.append(dataset[i])
    #     y_train.append(label[i])
    # x_test = dataset[1000:6000]
    # y_label = label[1000:6000]
    for i in range(3):
        clf_name = 'IForest'
        clf = IForest()
        clf.fit(x_train)

        # get the prediction label and outlier scores of the training data
        y_train_pred = clf.labels_  # binary labels (0: inliers, 1: outliers)
        y_train_scores = clf.decision_scores_  # raw outlier scores
        from sklearn.metrics import accuracy_score
        from sklearn.metrics import precision_score
        from sklearn.metrics import recall_score
        print(accuracy_score(y_train, y_train_pred))
        print(precision_score(y_train, y_train_pred))
        print(recall_score(y_train, y_train_pred))
        # get the prediction on the test data
        y_test_pred = clf.predict(x_test)  # outlier labels (0 or 1)
        y_test_scores = clf.decision_function(x_test)  # outlier scores

        # evaluate and print the results
        print("\nOn Training Data:")
        evaluate_print(clf_name, y_train, y_train_scores)
        print(accuracy_score(y_label, y_test_pred))
        print(precision_score(y_train, y_train_pred))
        print(recall_score(y_train, y_train_pred))
        print("\nOn Test Data:")
        evaluate_print(clf_name, y_label, y_test_scores)

    # visualize the results



if __name__ == "__main__":
    main()