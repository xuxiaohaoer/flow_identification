import numpy as np
import matplotlib.pyplot as plt

def draw_1():
    plt.rcParams['font.sans-serif']=['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    #matplotlib画图中中文显示会有问题，需要这两行设置默认字体

    plt.xlabel('X')
    plt.ylabel('Y')
    plt.xlim(xmax=55,xmin=10)
    plt.ylim(ymax=0.875,ymin=0.75)
    #画两条（0-9）的坐标轴并设置轴标签x，y


    # x1 = np.random.normal(2,1.2,300) # 随机产生300个平均值为2，方差为1.2的浮点数，即第一簇点的x轴坐标
    # y1 = np.random.normal(2,1.2,300) # 随机产生300个平均值为2，方差为1.2的浮点数，即第一簇点的y轴坐标
    # x2 = np.random.normal(7.5,1.2,300)
    # y2 = np.random.normal(7.5,1.2,300)
    x1 = [15,20,25,30,35,40,45,50]
    y1 = [0.7995, 0.8095, 0.834, 0.838, 0.8437, 0.84125, 0.83925, 0.84125]
    x2 = [15,20,25,30,35,40,45,50]
    y2 = [0.8637, 0.853, 0.8277, 0.84875, 0.85275, 0.84475, 0.8533, 0.86225]
    colors1 = '#00CED1' #点的颜色
    # colors2 = '#DC143C'
    area = np.pi * 4**2  # 点面积
    # 画散点图
    plt.plot(x1, y1)
    plt.plot(x2, y2)
    # plt.scatter(x2, y2, s=area, c=colors2, alpha=0.4, label='类别B')
    plt.show()

def draw_2():
    print('begin draw')
    x = ['payload', 'time', 'speed', 'flag', 'cipher', 'flow', 'subject', 'issue', 'matrix', 'mix', 'behavior', 'payload_seq', 'mix_seq', 'mix_seq_dir']
    y_acc = [0.852, 0.8222, 0.8247, 0.8257, 0.844, 0.8642, 0.9017, 0.8337, 0.8492, 0.878, 0.8562, 0.8325, 0.85, 0.864]
    y_pre = [0.8937, 0.8411, 0.8692, 0.8353, 0.7915, 0.8991, 0.8714, 0.8710, 0.8686, 0.8945, 0.8497, 0.8610, 0.8503,0.8537]
    y_rec = [0.799, 0.7945, 0.7645, 0.8115, 0.934, 0.8205, 0.9425, 0.7835, 0.823, 0.857, 0.8665, 0.793, 0.8495, 0.8785]
    print(len(x), len(y_rec))
    plt.bar(x,y_rec)
    plt.title('rec')
    plt.show()

def draw_hisogram():
    import seaborn as sns
    print('begin draw')
    features = ['mix_flow+matrix', 'behavior', 'matrix', 'mix', 'payload', 'flow', 'pay+beh']
    feature = features[2]
    print('this is made by {}'.format(feature))
    y_grade = np.load('grade/ae_grade_{}.npy'.format(feature))
    y_label = np.load('grade/ae_label_{}.npy'.format(feature))
    x_w, x_b, y_w, y_b = dataset_pre(y_grade, y_label)
    import matplotlib.pyplot as plt

    group = [ i for i in range(2,24,1)]

    # group = [2.5, 5, 7.5, 10, 12.5, 15, 17.5, 20, 22.5]
    plt.hist(y_w, group, histtype='bar',alpha=0.5, align='left', label='white')
    plt.hist(y_b, group, histtype='bar',alpha=0.5, align='right', label='black')
    # plt.bar(y_w, group, label='white')
    # plt.bar(y_b, group, label='black')
    # sns.displot(y_w, kde= 'false', color='steelblue', label ='white')
    # sns.displot(y_b, kde= 'false', color='purple',  label= 'black')


    plt.xlabel('number')
    plt.ylabel('grade')

    plt.title('{} hisogram'.format(feature))
    plt.legend()
    plt.show()

def dataset_pre(y_grade, y_label):
    x_w = []
    x_b = []
    y_w = []
    y_b = []
    for i in range(len(y_grade)):
        if y_label[i] == 0:
            y_w.append(y_grade[i])
            x_w.append(i)
        else:
            y_b.append(y_grade[i])
            x_b.append(i)

    return x_w, x_b, y_w, y_b[:1000]

def draw_line():
    print('begin draw')
    import numpy as np
    nth = 2
    features = ['mix_flow+matrix', 'behavior', 'matrix', 'mix', 'payload', 'flow', 'pay+beh']
    feature = features[-1]
    print('this is made by {}'.format(feature))
    y_grade = np.load('grade/ae_grade_{}.npy'.format(feature))
    y_label = np.load('grade/ae_label_{}.npy'.format(feature))

    x_w, x_b, y_w, y_b = dataset_pre(y_grade, y_label)
    y_w.sort()
    y_b.sort()
    x_w = [i for i in range(0,1000)]
    x_b = [i for i in range(0,1000)]



    plt.rcParams['font.sans-serif'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    # matplotlib画图中中文显示会有问题，需要这两行设置默认字体

    plt.xlabel('nth')
    plt.ylabel('grade')
    # plt.xlim(xmax=6000, xmin=0)
    # plt.ylim(ymax=20, ymin=0)
    # 画两条（0-9）的坐标轴并设置轴标签x，y

    # 画散点图
    plt.plot(x_b, y_b)
    plt.plot(x_w, y_w)
    plt.show()
    print('end draw')

def main():
    print('begin draw')
    import numpy as np
    nth = 2
    features = ['mix_flow+matrix', 'behavior' , 'matrix', 'mix', 'payload', 'flow', 'pay+beh']
    feature = features[-1]
    print('this is made by {}'.format(feature))
    y_grade = np.load('grade/ae_grade_{}.npy'.format(feature))
    y_label = np.load('grade/ae_label_{}.npy'.format(feature))

    x_w, x_b, y_w, y_b = dataset_pre(y_grade, y_label)
    plt.rcParams['font.sans-serif'] = ['SimHei']
    plt.rcParams['axes.unicode_minus'] = False
    # matplotlib画图中中文显示会有问题，需要这两行设置默认字体

    plt.xlabel('nth')
    plt.ylabel('grade')
    plt.xlim(xmax=6000, xmin=0)
    plt.ylim(ymax=20, ymin=0)
    # 画两条（0-9）的坐标轴并设置轴标签x，y

    colors1 = '#00CED1'  # 点的颜色
    colors2 = '#DC143C'
    area = np.pi * 4 ** 2  # 点面积
    # 画散点图
    plt.scatter(x_b, y_b, s=area, c=colors1, alpha=0.4, label='恶意')
    plt.scatter(x_w, y_w, s=area, c=colors2, alpha=0.4, label='正常')
    plt.legend()
    plt.show()
    print('end draw')


def draw_3():
    x = [10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65, 70, 75]
    Y1 = [[0.8958, 0.91, 0.9112, 0.9035, 0.9008, 0.9022, 0.8968, 0.895, 0.8995, 0.8942, 0.8955, 0.8922, 0.8965, 0.8942],
         [0.827, 0.88, 0.879, 0.8892, 0.8972, 0.8968, 0.9018, 0.8982, 0.894, 0.8948, 0.891, 0.8928, 0.892, 0.8908]]
    Y2 = [[0.8742, 0.8849, 0.8824, 0.8799, 0.88, 0.8761, 0.8696, 0.8648, 0.8716, 0.8603, 0.8646, 0.8581, 0.8641, 0.8646],
          [0.7662, 0.8519, 0.8687, 0.8692, 0.8697, 0.8699, 0.8729, 0.8683, 0.8602, 0.862, 0.8565, 0.8605, 0.8584,
           0.8558]]
    Y3 = [[0.9252, 0.9432, 0.9497, 0.9352, 0.9287, 0.9377, 0.9342, 0.9372, 0.9377, 0.9422, 0.9387, 0.9407, 0.9417, 0.9357],
          [0.9427, 0.9207, 0.8938, 0.9172, 0.9352, 0.9337, 0.9412, 0.9397, 0.9417, 0.9407, 0.9402, 0.9382, 0.9397, 0.9407]]
    Y = [0.8968, 0.895, 0.9005, 0.8945, 0.8938, 0.8898, 0.8958, 0.8815, 0.8895, 0.8762, 0.8742, 0.8785, 0.884, 0.878, 0.8798]
    # for y in Y3:
    #     plt.plot(x, y)
    Y_payload =[0.8958, 0.91, 0.9112, 0.9035, 0.9008, 0.9022, 0.8968, 0.895, 0.8995, 0.8942, 0.8955, 0.8922, 0.8965, 0.8942]
    Y_mix_dir =[0.827, 0.88, 0.879, 0.8892, 0.8972, 0.8968, 0.9018, 0.8982, 0.894, 0.8948, 0.891, 0.8928, 0.892, 0.8908]
    Y_change = [0.8595, 0.8808, 0.8985, 0.9038, 0.9045, 0.9048, 0.8995, 0.8988, 0.8998, 0.902, 0.9012, 0.9035, 0.9038, 0.9042]
    plt.plot(x, Y_payload)
    plt.plot(x, Y_mix_dir)
    plt.plot(x, Y_change)
    plt.xlabel('length')
    plt.legend(('payload', 'behavior' ,'behavior_c'))
    plt.title("acc")
    plt.show()



if __name__ == '__main__':
    # main()
    draw_3()

