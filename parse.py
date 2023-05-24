from abnf.grammars import rfc5234
import os

def read_rulelist(file_path):
    with open(file_path, 'r') as f:
        file_str = f.read()
        rules = file_str.split('\n\n')
    return rules

def write_list_txt(rulelist, file_path):
    with open(file_path, "w") as f_out:
        for i, rule_lines in enumerate(rulelist):
            if i > 0:
                # 每个ABNF规则之间空一行
                f_out.write("\n")
            for l in rule_lines:
                f_out.write(l)
        if rulelist:
            # 最后一个ABNF规则之后不需要再空一行
            f_out.write("\n")



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
    input_folder = "converted"
    valid_folder = "parse_out"
    invalid_folder = "parse_invalid"
    for i in range(4018,9999):
        file_path =  f'{input_folder}/rfc{i}.txt'

        parse_out_path = f'{valid_folder}/rfc{i}.txt'
        invalid_path = f'{invalid_folder}/rfc{i}.txt'

        if os.path.exists(file_path):
            print(i)
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
