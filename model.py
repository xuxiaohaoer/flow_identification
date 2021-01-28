from sklearn.ensemble import RandomForestClassifier
# from xgboost.sklearn import XGBClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.model_selection import GridSearchCV
# import lightgbm as lgb
from scipy.stats import randint
import numpy as np
from sklearn.model_selection import RandomizedSearchCV
import time

def RandomForest(x_train, y_train, x_test):
    y_pred = []
    rnd = RandomForestClassifier()
    param_dist = {
        "n_estimators": range(200, 300, 25),
        "max_depth": [3, None],
        "min_samples_split": range(2, 10, 2),
        "max_leaf_nodes": range(100, 300, 20),
        "criterion": ['gini', 'entropy']
    }  # 随机搜索

    # parameters = {"n_estimators": range(100, 300, 50)}  # 网格搜索
    # rnd_clf = GridSearchCV(rnd, param_dist)

    rnd_clf = RandomForestClassifier(n_estimators=300, max_leaf_nodes=150, n_jobs=-1) # 最初的模型
    # rnd_clf = RandomizedSearchCV(rnd, param_distributions=param_dist, n_iter=10)

    rnd_clf.fit(x_train, y_train)
    # print(rnd_clf.best_estimator_)
    y_pred = rnd_clf.predict(x_test)
    # for sample in x_test:
    #     y_pred.append(rnd_clf.predict([sample]))
    return y_pred


def GradientBoosting(x_train, y_train, x_test):
    y_pred = []
    gbm = GradientBoostingClassifier()
    param_dist = {
        "n_estimators": range(150, 300, 50),
        "min_samples_leaf": range(2, 10, 5),
        "max_depth": [3, 4, None],
        "max_leaf_nodes": range(100, 300, 100),
    }
    # gbm_clf = RandomizedSearchCV(gbm, param_distributions=param_dist, n_iter=10)


    gbm_clf= GradientBoostingClassifier(n_estimators=200, random_state=10, subsample=0.6)
    gbm_clf.fit(x_train, y_train)
    # print(gbm_clf.best_estimator_)
    y_pred = gbm_clf.predict(x_test)
    # for sample in x_test:
    #     y_pred.append(gbm.predict([sample]))
    return y_pred


def Voting(x_train, y_train, x_test):
    y_pred = []
    rnd = RandomForestClassifier(n_estimators=225, max_leaf_nodes=220, criterion='entropy')
    gbm = GradientBoostingClassifier(n_estimators=250, max_leaf_nodes=100, min_samples_leaf=2, max_depth=4)
    voting_clf = VotingClassifier(estimators=[('lr', rnd), ('rf', gbm)], voting='soft')
    voting_clf.fit(x_train, y_train)
    y_pred = voting_clf.predict(x_test)
    # for sample in x_test:
    #     y_pred.append(voting_clf.predict([sample]))
    return y_pred


def KmeansCluster(X):
    from sklearn.cluster import KMeans
    kmeans = KMeans()
    param_dist = {
        "n_clusters":range(10,50,10),
    }
    kmeans_model = RandomizedSearchCV(kmeans, param_dist, n_iter=3)
    kmeans_model.fit(X)
    print(kmeans_model.best_estimator_)
    y_pred = kmeans_model.predict(X)
    return y_pred


def DbscanCluster(x_train, x_test):
    from sklearn.cluster import DBSCAN
    dbscan =DBSCAN(eps=0.3, min_samples=10)
    dbscan.fit(x_train)
    y_pred = dbscan.fit_predict(x_test)
    return y_pred


def Xgboost(x_train, y_train, x_test):
    y_pred = []
    xgb = XGBClassifier()
    x_train = np.array(x_train)
    y_train = np.array(y_train)
    xgb.fit(x_train, y_train)
    y_pred = (xgb.predict(x_test))
    # for sample in x_test:
    #     y_pred.append(xgb.predict([sample]))
    return y_pred


def LightGBM(x_train, y_train, x_test, y_label):
    for i in range(len(y_train)):
        if y_train[i] == 'white':
            y_train[i] = 0
        if y_train[i] == 'black':
            y_train[i] = 1
    for i in range(len(y_label)):
        if y_label[i] == 'white':
            y_label[i] = 0
        if y_label[i] == 'black':
            y_label[i] = 1
    x_train = np.array(x_train)
    y_train = np.array(y_train)
    x_test = np.array(x_test)
    y_label = np.array(y_label)

    y_pred = []
    lgb_train = lgb.Dataset(x_train, y_train)  # 将数据保存到LightGBM二进制文件将使加载更快
    lgb_eval = lgb.Dataset(x_test, y_label, reference=lgb_train)
    params = {'num_leaves': 60,  # 结果对最终效果影响较大，越大值越好，太大会出现过拟合
              'min_data_in_leaf': 30,
              'objective': 'binary',  # 定义的目标函数
              'max_depth': -1,
              'learning_rate': 0.03,
              "min_sum_hessian_in_leaf": 6,
              "boosting": "gbdt",
              "feature_fraction": 0.9,  # 提取的特征比率
              "bagging_freq": 1,
              "bagging_fraction": 0.8,
              "bagging_seed": 11,
              "lambda_l1": 0.1,  # l1正则
              # 'lambda_l2': 0.001,     #l2正则
              "verbosity": -1,
              "nthread": -1,  # 线程数量，-1表示全部线程，线程越多，运行的速度越快
              'metric': {'binary_logloss', 'auc'},  ##评价函数选择
              "random_state": 2019,  # 随机数种子，可以防止每次运行的结果不一致
              # 'device': 'gpu' ##如果安装的事gpu版本的lightgbm,可以加快运算
              }
    gbm = lgb.train(params, lgb_train, num_boost_round=20, valid_sets=lgb_eval, early_stopping_rounds=5)
    y_pred = gbm.predict(x_test)
    Y_test = []
    for i in range(len(y_pred)):
        if y_pred[i] < 0.5:
            Y_test.append(0)
        else:
            Y_test.append(1)
    return Y_test

