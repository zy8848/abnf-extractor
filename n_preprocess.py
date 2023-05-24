import re
import os
import csv
from abnf.grammars import rfc5234

input_folder = 'regexp_output'
output_folder = 'converted'


def abnf_transform(abnf_rule):
    def expand_repeats(match):
        min_count, max_count, element = match.groups()
        min_count = int(min_count) if min_count else 0
        max_count = int(max_count) if max_count else float("inf")
        if min_count>100:
            print(f"Skip, because it looks like not a abnf: {match.group(0)}")
            return match.group(0)

        if max_count == float('inf'):
            repetitions = [element for _ in range(min_count)]
            # return "(" + " ".join(repetitions) + " *(" + " " + element + "))"
            return  " ".join(repetitions) + " *(" + " " + element + ")"
        else:
            # 暂时不考虑这种情况
            print("cannot convert")
            return match.group(0)
            
    
    transformed_abnf = re.sub(r'(\d*)#(\d*)\(([^)]+)\)', expand_repeats, abnf_rule)
    transformed_abnf = re.sub(r'(\d*)#(\d*)([A-Za-z][A-Za-z0-9-]*)', expand_repeats, transformed_abnf)
    return transformed_abnf


def write_list_txt(rulelist, file_path):
    with open(file_path, "w") as f_out:
        for i, rule_lines in enumerate(rulelist):
            if i > 0:
                # 每个ABNF规则之间空一行
                f_out.write("\n\n")
            for l in rule_lines:
                f_out.write(l)
        if rulelist:
            # 最后一个ABNF规则之后不需要再空一行
            f_out.write("\n")


def convert_one_file(rfc_i):
    with open(f"{input_folder}/rfc{rfc_i}.txt", 'r') as f:
        file_str = f.read()
        rules = file_str.split('\n\n')


    ori = []
    transformed = []
    for i,rule in enumerate(rules):
        # rule += "\n"
        # rule = rule.replace("\n","\r\n")
        if '#' in rule:
            new_rule = abnf_transform(rule)
            rules[i] = new_rule
            if new_rule != rule:
                ori.append(rule)
                transformed.append(new_rule)
            
    
    write_list_txt(rules,f"{output_folder}/rfc{rfc_i}.txt")
    
    
    




if __name__ == "__main__":
    data = []
    for i in range(1,9999):
        file_path =  f'{input_folder}/rfc{i}.txt'
        if os.path.exists(file_path):
            print(i)
            convert_one_file(i)



    # with open('data.csv', mode='w', newline='') as file:
    #     fieldnames = ['rfc_num', 'origin', 'transformed']
    #     writer = csv.writer(file)
    #     writer.writerow(fieldnames)
    #     for row in data:
    #         writer.writerow(row)    
