import numpy as np
d_train_w = np.load("feature_flow/train_white.npy", allow_pickle=True)
d_train_b = np.load("feature_flow/train_black.npy", allow_pickle=True)
d_test_w = np.load("feature_flow/test_white.npy", allow_pickle= True)
d_test_b = np.load("feature_flow/test_black.npy", allow_pickle= True)


print(len(d_train_w) ,len(d_test_w))
print(len(d_test_b) + len(d_train_b))