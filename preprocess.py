import re
import os
import csv
import glob
from data_utils import write_list_txt
from tqdm import tqdm


input_folder = 'abnf/regexp_out'
output_folder = 'abnf/converted'


def abnf_transform(abnf_rule):
    def expand_repeats(match):
        min_count, max_count, element = match.groups()
        min_count = int(min_count) if min_count else 0
        max_count = int(max_count) if max_count else float("inf")

        if max_count == float('inf'):
            repetitions = [element for _ in range(min_count)]
            return  " ".join(repetitions) + " *(" + " " + element + ")"
        else:
            # 暂时不考虑这种情况
            return match.group(0)
            
    
    transformed_abnf = re.sub(r'(\d*)#(\d*)\(([^)]+)\)', expand_repeats, abnf_rule)
    transformed_abnf = re.sub(r'(\d*)#(\d*)([A-Za-z][A-Za-z0-9-]*)', expand_repeats, transformed_abnf)
    return transformed_abnf



def convert_one_file(rfc_i):
    with open(f"{input_folder}/rfc{rfc_i}.txt", 'r') as f:
        file_str = f.read()
        rules = file_str.split('\n\n')


    ori = []
    transformed = []
    for i,rule in enumerate(rules):
        if '#' in rule:
            match = re.search(r'(\d*)#(\d*)', rule)
            min_count = int(match.group(1)) if match.group(1) else 0

            if min_count > 100:
                #print(f"Skip, because it looks like not a abnf: {rule}")
                continue

            new_rule = abnf_transform(rule)
            rules[i] = new_rule
            if new_rule != rule:
                ori.append(rule)
                transformed.append(new_rule)
            
    
    write_list_txt(rules,f"{output_folder}/rfc{rfc_i}.txt")
    
    
    




if __name__ == "__main__":
    data = []
    txt_files = glob.glob(input_folder + "/*.txt")
    os.makedirs(output_folder, exist_ok=True)
    for file_path in tqdm(txt_files):
        match = re.search(r'rfc(\d+)\.txt', file_path)
        num = int(match.group(1)) if match else None
        convert_one_file(num)
    
    print(f"{len(txt_files)} files have been processed")



    # with open('data.csv', mode='w', newline='') as file:
    #     fieldnames = ['rfc_num', 'origin', 'transformed']
    #     writer = csv.writer(file)
    #     writer.writerow(fieldnames)
    #     for row in data:
    #         writer.writerow(row)    
