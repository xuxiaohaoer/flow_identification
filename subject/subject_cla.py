import csv


if __name__ == "__main__":
    print("system begin")
    black = {}
    with open("./subject_black.csv", 'r') as f:
        reader = csv.reader(f)
        reader = list(reader)
        for item in reader:
            for key in item:
                if key not in black.keys():
                    black[key] = 1
                else:
                    black[key] += 1
        black_order = sorted(black.items(), key=lambda x: x[1], reverse=True)
        print(black_order)
    white = {}
    with open("./subject_white.csv", 'r') as f:
        reader = csv.reader(f)
        reader = list(reader)
        for item in reader:
            for key in item:
                if key not in white.keys():
                    white[key] = 1
                else:
                    white[key] += 1
        white_order = sorted(white.items(), key=lambda x: x[1], reverse=True)
        print(white_order)





