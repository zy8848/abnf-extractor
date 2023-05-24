import csv
import os
from data_utils import write_list_txt,read_rulelist




def is_constant(input_str):
    # 检查字符串长度是否大于15
    if len(input_str) > 40:
        return True
    
    # 检查字符串是否为十六进制数
    try:
        int(input_str, 16)
        return True
    except ValueError:
        return False


def remove_constant(rulelist):
    # 创建一个新的rulelist用于存储处理过的规则
    processed_rulelist = []
    deleted_rules = []

    for rule in rulelist:
        # 解析每个规则的等号右边的rulename
        rule_parts = rule.split('=')
        rulename = rule_parts[0].strip()
        righthand_side = rule_parts[1].strip()

        # 检查等号右边的每个rulename是否为常量
        is_constant_present = False
        for rname in righthand_side.split():
            if is_constant(rname):
                is_constant_present = True
                break

        # 如果没有常量，则将该规则添加到处理过的rulelist中
        if not is_constant_present:
            processed_rulelist.append(rule)
        else:
            deleted_rules.append(rule)

    # 返回处理过后的rulelist
    return processed_rulelist, deleted_rules
        

if __name__ == "__main__":

    # 删除包含特别长constant的rule
    input_folder = "parse_out"

    output_folder = "postprocess"
    
    data = []
    for i in range(5259,9999):
        file_path =  f'{input_folder}/rfc{i}.txt'


        if os.path.exists(file_path):
            print(i)
            rulelist = read_rulelist(file_path)
            processed_rulelist, deleted_rules = remove_constant(rulelist)
            write_list_txt(processed_rulelist,f"{output_folder}/rfc{i}.txt")

            for rule in deleted_rules:
                data.append((i,rule))    



    with open('csv_files/removed_constant.csv', mode='w', newline='') as file:
        fieldnames = ['rfc_num', 'rule']
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        for row in data:
            writer.writerow(row)    