import pre
import numpy as np
x_black = pre.pre_pcap("data/eta_1/train/black/")
x_white = pre.pre_pcap("data/eta_1/train/white/")

f = open("feature_list", 'w+')
f.write(x_black)
f.write(x_white)

