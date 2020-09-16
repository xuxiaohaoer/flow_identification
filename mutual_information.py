import dataset
import numpy as np
from sklearn import metrics
x_train, y_train, x_test, y_label = dataset.pre_data()
x = x_train + x_test
y = y_train + y_label
tem = np.array(x)
for i in range(len(tem[0])):
    mutual = metrics.mutual_info_score(x[:, i], y)
    print(i, mutual)
