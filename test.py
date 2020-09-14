# import xgboost
# print('a', xgboost.__version__)

class feature_type:
    def __init__(self,flow_num, flow_size,flow_starttime,flow_endtime):
        self.flow_num = flow_num
        self.flow_size = flow_size
        self.flow_duration = 0
        self.flow_starttime = flow_starttime
        self.flow_endtime = flow_endtime

def main():
    contact = {}
    a = {"1,2,3,4"}
    b = feature_type(0,0,0,0)
    contact['1,2,3,4'] = b
    dict = {'Name': 'Zara', 'Age': 7}
    if contact.__contains__('1,2,3,4'):
        print("abc")
    print(b)
    print(contact['1,2,3,4'].flow_num)

if __name__ == "__main__":
    main()
