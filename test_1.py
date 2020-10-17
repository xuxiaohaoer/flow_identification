import torch
from sklearn.preprocessing import MinMaxScaler
import numpy as np
x =[[0, 1.1, 2],[0,1,3],[0,1,4]]
minMax = MinMaxScaler()
x_scale = minMax.fit_transform(x)
print(x_scale)