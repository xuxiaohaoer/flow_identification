import json
from sklearn.preprocessing import MinMaxScaler
import csv
x_train = []
x_test = []
def data_read():
    minMax = MinMaxScaler()
    with open('feature_list_train.csv', 'r',) as f:
        reader = csv.reader(f)
        x_train = list(reader)
        # x_black = json.loads(tem)
        # x_black = minMax.fit_transform(json.loads(tem))
    f.close()
    with open('feature_list_test.csv', 'r') as f:
        reader = csv.reader(f)
        x_test = list(reader)
        # x_white = json.loads(tem)
        # x_white = minMax.fit_transform(json.loads(tem))
    f.close
    return x_train, x_test