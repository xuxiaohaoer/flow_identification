import json
from sklearn.preprocessing import MinMaxScaler
def data_read():
    minMax = MinMaxScaler()
    with open('feature_list_b', 'r') as f:
        tem = f.read()
        # x_black = json.loads(tem)
        x_black = minMax.fit_transform(json.loads(tem))
    f.close()
    with open('feature_list_w', 'r') as f:
        tem = f.read()
        # x_white = json.loads(tem)
        x_white = minMax.fit_transform(json.loads(tem))
    f.close
    return x_black, x_white