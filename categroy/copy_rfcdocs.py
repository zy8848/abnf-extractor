import os
import shutil
import csv

rfc_dict = {}
with open('csv_files/rfc_categroy_1.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        rfc_dict[int(row['rfc_num'])] = row['categroy']


source_path = 'cross_def/'
destination_path = 'abnf/cross_def/'

# 创建目标文件夹如果它还不存在
os.makedirs(destination_path, exist_ok=True)

# 遍历rfc_dict字典
for num, category in rfc_dict.items():
    # 如果分类为'complete_set'，则复制文件
    if category == 'cross_def':
        source_file = os.path.join(source_path, f'rfc{num}.txt')
        destination_file = os.path.join(destination_path, f'rfc{num}.txt')
        shutil.copy2(source_file, destination_file)

print("Files copied.")