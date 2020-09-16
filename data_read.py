import json
def data_read():
    with open('feature_list_b', 'r') as f:
        tem = f.read()
        x_black = json.loads(tem)
    f.close()
    with open('feature_list_w', 'r') as f:
        tem = f.read()
        x_white = json.loads(tem)
    f.close
    return x_black, x_white