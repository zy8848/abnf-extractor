from abnf.grammars import rfc5234
import os
import glob
import re
from data_utils import read_rulelist,write_list_txt
from tqdm import tqdm

def get_rulename_from_node(node):
    """Do a breadth-first search of the tree for addr-spec node.  If found, 
    return its value."""
    rulenames = []
    queue = [node]
    while queue:
        n, queue = queue[0], queue[1:]
        if n.name == 'rulename':
            rulenames.append(n.value)
        
        queue.extend(n.children)
    return rulenames

def get_dependence_rulename(rule): # 找到一条rule里等号右侧的所有rulename


    parser = rfc5234.Rule('rule')
    node = parser.parse_all(rule)
    name_list = get_rulename_from_node(node)
    return name_list




def can_parse(rule):
    parser = rfc5234.Rule('rule')

    try:
        node = parser.parse_all(rule)
        return True
    except:
        return False







def process_file(file_path):
    rulelist = read_rulelist(file_path)
    valid_rule = []
    invalid_rule = []
    

    for i,rule in enumerate(rulelist):
        rule += "\n"
        rule = rule.replace("\n","\r\n")
        rulelist[i] = rule

    for rule in rulelist:
        is_valid = can_parse(rule)
        if is_valid:
            valid_rule.append(rule)
        else:
            invalid_rule.append(rule)
    
    return valid_rule,invalid_rule


if __name__ == "__main__":
    input_folder = "abnf/converted"
    valid_folder = "abnf/parse_out"
    invalid_folder = "abnf/parse_invalid"

    os.makedirs(valid_folder, exist_ok=True)
    os.makedirs(invalid_folder, exist_ok=True)

    txt_files = glob.glob(input_folder + "/*.txt")
    for file_path in tqdm(txt_files):
        match = re.search(r'rfc(\d+)\.txt', file_path)
        i = int(match.group(1)) if match else None

        file_path =  f'{input_folder}/rfc{i}.txt'

        parse_out_path = f'{valid_folder}/rfc{i}.txt'
        invalid_path = f'{invalid_folder}/rfc{i}.txt'


        valid_rule, invalid_rule = process_file(file_path)
        if valid_rule:
            write_list_txt(valid_rule,parse_out_path)
        if invalid_rule:
            write_list_txt(invalid_rule,invalid_path)



# import os
# import concurrent.futures


# def process_single_file(i):
#     input_folder = "converted"
#     valid_folder = "parse_out"
#     invalid_folder = "parse_invalid"
    
#     file_path = f'{input_folder}/rfc{i}.txt'
#     parse_out_path = f'{valid_folder}/rfc{i}.txt'
#     invalid_path = f'{invalid_folder}/rfc{i}.txt'
    
#     if os.path.exists(file_path):
#         print(i)
#         if os.path.exists(parse_out_path):
#             print(f"skip{i}")
#             return
#         valid_rule, invalid_rule = process_file(file_path)
#         if valid_rule:
#             write_list_txt(valid_rule, parse_out_path)
#         if invalid_rule:
#             write_list_txt(invalid_rule, invalid_path)

# def parallel_file_processing():
#     with concurrent.futures.ThreadPoolExecutor() as executor:
#         executor.map(process_single_file, range(1, 10000))

# # 调用并行文件处理函数
# parallel_file_processing()
