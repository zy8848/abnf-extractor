# 处理1000个文件
from data_utils import read_rulelist
from n_cross_def import get_dependence_rulename
import os



def get_list(file_path):
    rulelist = read_rulelist(file_path)
    list_2d = []
    for rule in rulelist:
        rule += "\n"
        rule = rule.replace("\n","\r\n")

        name_list = get_dependence_rulename(rule)
        list_2d.append(name_list)
    return list_2d

def write_list_to_file(data, output_file):
    # 将二维列表写入文本文件
    
    with open(output_file, 'w') as file:
        for sublist in data:
            file.write(','.join(sublist) + '\n')



def read_file(file_path):
    # 读取文件内容并返回一个二维列表
    
    # 示例代码
    with open(file_path, 'r') as file:
        lines = file.readlines()
        data = [line.strip().split(',') for line in lines]
    
    return data


for i in range(1, 9999):

    input_file = f"parse_out/rfc{i}.txt"
    output_file = f"names/rfc{i}.txt"

    # 从文件中获取列表
    if os.path.exists(input_file):
        print(i)
        data = get_list(input_file)

        write_list_to_file(data, output_file)



