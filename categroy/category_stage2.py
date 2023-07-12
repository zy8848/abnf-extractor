# 对于U>D U<D几种分类
import csv
# from data_utils import read_rulelist
from write_names import read_file
import os


def get_D_U(rulenames_2d): # get number of defined and undefined

    left_part = []
    right_part = []
    for rulenames in rulenames_2d:

        left_part.append(rulenames[0])
        right_part.extend(rulenames[1:])
    
    left_set = set(left_part)
    right_set = set(right_part)

    
    invalid_names = right_set - left_set
    return len(left_set),len(invalid_names)


rfc_dict = {}

# 从CSV文件读取数据并存入字典
with open('csv_files/rfc_categroy.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        rfc_dict[int(row['rfc_num'])] = row['categroy']






for num, value in rfc_dict.items():
    fp = f"names/rfc{num}.txt"
    if value == '0' and os.path.exists(fp):
        rulenames_2d = read_file(fp)
        n_defined, n_undefined = get_D_U(rulenames_2d)
        if n_defined >= n_undefined:
            rfc_dict[num] = "D>=U"
        elif n_defined == 0:
            rfc_dict[num] = "D==0"
        else:
            rfc_dict[num] = "D<U"


with open('csv_files/rfc_categroy_1.csv', 'w', newline='') as csvfile:
    fieldnames = ['rfc_num', 'categroy']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for key, value in rfc_dict.items():
        writer.writerow({'rfc_num': key, 'categroy': value})

from collections import Counter

# 计算rfc_dict中每种分类的个数
category_counts = Counter(rfc_dict.values())

print(category_counts)
