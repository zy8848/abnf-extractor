import os
import re
import csv
from collections import OrderedDict

def is_non_empty_file(file_path):
    try:
        with open(file_path, 'r') as file:
            content = file.read()
            if content:
                return True
            else:
                return False
    except FileNotFoundError:
        print("文件未找到！")
        return False


# -----------------检查regexp---------------#

rfc_path = 'rfc_docs/'
regexp_output_path = 'regexp_output/'

# 获取文件夹下所有文件，并用正则表达式匹配rfc文档
file_list = os.listdir(rfc_path)
rfc_files = [f for f in file_list if re.match(r'rfc\d+.txt', f)]

# 创建字典，num为key，初始value为0，同时按key进行排序
rfc_dict = OrderedDict(sorted({int(re.findall(r'\d+', f)[0]): 0 for f in rfc_files}.items()))

# 获取'regexp_output/'文件夹下所有文件，并用正则表达式匹配rfc文档
regexp_output_files = os.listdir(regexp_output_path)
regexp_rfc_files = [f for f in regexp_output_files if re.match(r'rfc\d+.txt', f)]

# 如果在'regexp_output/'文件夹中存在'rfc{num}.txt'，则将value置为'no_reg_matching'
for num in rfc_dict:
    if f'rfc{num}.txt' not in regexp_rfc_files:
        rfc_dict[num] = 'no_reg_matching'



# -----------------检查parse_out---------------#
invalid_path = 'parse_invalid/'
for num, value in rfc_dict.items():
    if value == 0:
        file_name = f'rfc{num}.txt'
        if file_name in os.listdir(invalid_path):
            with open(os.path.join(invalid_path, file_name), 'r') as file:
                content = file.read().strip()
                if content:  # 如果文件非空
                    rfc_dict[num] = 'parse_invalid'


# --------------def check----------------------
from write_names import read_file
from cross_def import get_def_dict,get_group_names
from data_utils import read_rulelist
rule_dict = get_def_dict("parse_out")

def is_complete_ruleset(rulenames_2d): 

    left_part = []
    right_part = []
    for rulenames in rulenames_2d:

        left_part.append(rulenames[0])
        right_part.extend(rulenames[1:])
    
    left_set = set(left_part)
    right_set = set(right_part)

    result = right_set.issubset(left_set)
    
    invalid_names = right_set - left_set
    return result,invalid_names


def get_groupname_in_file(rfc_num): # 从rfc文件中获取所有在group的名字
    rulelist = read_rulelist(f"parse_out/rfc{num}.txt")
    group_names = []
    for rule in rulelist:
        rule += "\n"
        rule = rule.replace("\n","\r\n")
        group_names.extend(get_group_names(rule))
    
    return group_names

for num, value in rfc_dict.items():
    fp = f"names/rfc{num}.txt"
    
    if value == 0 and os.path.exists(fp):
        rulenames_2d = read_file(fp)
        is_comp, undef_name = is_complete_ruleset(rulenames_2d)
        group_names = set(get_groupname_in_file(num))
        if is_comp:
            rfc_dict[num] = "complete_set"
        else:
            if undef_name.issubset(rule_dict):
                rfc_dict[num] = "cross_def"
            elif group_names and group_names.issubset(undef_name): # group name所有都是未定义的
                rfc_dict[num] = "common_in_bracket"
            else:
                pass



with open('csv_files/rfc_categroy.csv', 'w', newline='') as csvfile:
    fieldnames = ['rfc_num', 'categroy']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for key, value in rfc_dict.items():
        writer.writerow({'rfc_num': key, 'categroy': value})


# -------------comment in bracket -------------
# for num, value in rfc_dict.items():
#     fp = f"names/rfc{num}.txt"
#     if value == 0 and os.path.exists(fp):