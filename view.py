import pre
import matplotlib.pyplot as plt
from pylab import plot, show
x_black = pre.pre_pcap("data/eta_1/train/black/")
x_white = pre.pre_pcap("data/eta_1/train/white/")
x = []
y = []
for sample in x_black:
    x.append(sample[0])
    y.append(sample[3])
plot(x, y, 'bo')
x = []
y = []
for sample in x_white:
    x.append(sample[0])
    y.append(sample[3])
plot(x, y, "ro")
show()