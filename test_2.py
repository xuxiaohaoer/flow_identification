with open("data/eta/datacon_eta/test_label/black.txt", 'r') as f:
    tem = f.read()
    print("192.168.254.249" in tem)