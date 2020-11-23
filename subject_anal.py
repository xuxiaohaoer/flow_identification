import pre
import csv
x_black = pre.pre_pcap("data/eta/datacon_eta/train/black/", "black")


with open("subject_black.csv", 'w+', newline='') as f:
    f_csv = csv.writer(f)
    for key in x_black:
        f_csv.writerow(key[0])
f.close()
print("subject_black_done")

with open("issue_black.csv", 'w+', newline='') as f:
    f_csv = csv.writer(f)
    for key in x_black:
        f_csv.writerow(key[1])
f.close()
print("iss_black_done")

# x_white = pre.pre_pcap("data/eta/datacon_eta/train/white/", "white")
# with open("subject_white.csv", 'w+', newline='') as f:
#     f_csv = csv.writer(f)
#     for key in x_white:
#         f_csv.writerow(key[0])
# f.close()
# print("subject_white_done")
#
#
#
# with open("issue_black.csv", 'w+', newline='') as f:
#     f_csv = csv.writer(f)
#     for key in x_white:
#         f_csv.writerow(key[1])
# f.close()
# print("iss_white_done")