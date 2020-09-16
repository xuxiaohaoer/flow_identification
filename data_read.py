import json

with open('feature_lsit_b', 'r') as f:
    tem = f.read()
    x_black = json.loads(tem)
    print(x_black)