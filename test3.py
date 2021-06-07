import numpy as np
d_train_w = np.load("feature_flow/train_white.npy", allow_pickle=True)
d_train_b = np.load("feature_flow/train_black.npy", allow_pickle=True)
d_test_w = np.load("feature_flow/test_white.npy", allow_pickle= True)
d_test_b = np.load("feature_flow/test_black.npy", allow_pickle= True)

d_b = np.vstack((d_train_b,d_test_b))
d_w = np.vstack((d_train_w ,d_test_w))
num_b = 0
num_w = 0

for key in d_b:
    if (key[-3]==0):
        num_b +=1
for key in d_w:
    if (key[-3]==0):
        num_w +=1
print(num_b, num_w)