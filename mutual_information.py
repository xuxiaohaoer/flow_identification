import dataset
import numpy as np
from sklearn import metrics
# x_train, y_train, x_test, y_label = dataset.pre_data()
# x = x_train + x_test
# y = y_train + y_label
x = [[1,2,3], [2,3,4], [3,4,5]]
y = [0,1,0]

tem = np.array(x)
for i in range(x[0]):
    mutual = metrics.mutual_info_score(x[:i], y)
    print(i, tem)
