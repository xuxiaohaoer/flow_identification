import pre
import _json
import json
import numpy as np
x_black = pre.pre_pcap("data/eta_1/train/black/")
x_white = pre.pre_pcap("data/eta_1/train/white/")
f = open("feature_list_b", 'w+')
x_b = json.dumps(x_black)
f.write(x_b)
f.close()
f = open("feature_list_w", 'w+')
x_w = json.dumps(x_white)
f.write(x_w)
f.close()




