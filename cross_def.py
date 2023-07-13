import os
import csv
from data_utils import read_rulelist, write_list_txt
import abnf
import re
import glob
from tqdm import tqdm
from abnf.grammars import rfc5234


def check_names_definition_simple(rulelist): 
    #
    # parse每一个rule，
    # 把所有等号左边的记录下来，
    # 检查每个等号右边的name，如果符合rulename的定义，则
    
    import abnf
    valid_name = set()
    invalid_name = set()
    # abnf_rules = [
    #     "ALPHA", "BIT", "CHAR", "CR", "CRLF", "CTL", "DIGIT", "DQUOTE", "HEXDIG",
    #     "HTAB", "LF", "OCTET", "SP", "VCHAR", "WSP", "element", "ALTERNATIVE",
    #     "CONCATENATION", "OPTIONAL", "REPEAT"
    # ]


    left_part = []
    right_part = []
    for rule in rulelist:
        parts = rule.split("=")
        left_part.append(parts[0].strip())
        right_part.append(parts[1].strip())
        valid_name.add(parts[0].strip())
    
    for right in right_part:
        if ";" in right:
            right = right.split(";")[0]
        for name in right.split():
            try:
                node = abnf.parser.ABNFGrammarRule("rulename").parse_all(name)
                if name not in valid_name:
                    invalid_name.add(name)
            except:
                pass




    return valid_name, invalid_name


def get_undefined_names(rulelist,rule_dict): 
    data = [] # (rule,"name1, name2, ...")
    
    valid_name = set()
    for rule in rulelist:
        parts = rule.split("=")
        valid_name.add(parts[0].strip())

    undefined_all = []
    for rule in rulelist:
        parts = rule.split("=")
        right = parts[1].strip()

        if ";" in right:
            right = right.split(";")[0]
        
        undefined_names = []
        for name in right.split():
            try:
                node = abnf.parser.ABNFGrammarRule("rulename").parse_all(name)
                if name not in valid_name and name not in rule_dict :
                    undefined_names.append(name)
                    undefined_all.append(name)
            except:
                pass
        if undefined_names:
            data.append((rule," ".join(undefined_names),len(undefined_names)))
    return data, undefined_all

    



def get_def_dict(folder_path):
    result_dict = {}
    for filename in os.listdir(folder_path):
        if filename.endswith('.txt') and filename.startswith('rfc'):
            rfc_num = filename[3:-4]
            with open(os.path.join(folder_path, filename), 'r') as f:
                file_str = f.read()
                rules = file_str.split('\n\n')
                for rule in rules:
                    rule = rule.strip()
                    if '=' in rule:
                        rule_name = rule.split('=')[0].strip()
                        result_dict[rule_name] = {
                            'rule':rule,
                            'src':rfc_num
                        }
    return result_dict


def remove_duplicate(rulelist):
    # 初始化一个字典来保存rule和它出现的次数
    rule_dict = {}
    # 初始化一个列表来保存被删除的rule
    deleted_rules = []
    
    # 遍历规则列表
    for rule in rulelist:
        # 提取每一个规则名称，即等号左边的部分
        rule_name = rule.split('=')[0].strip()
        
        # 如果这个规则名称在字典中还没有出现过，就将它和对应的rule添加到字典中
        if rule_name not in rule_dict:
            rule_dict[rule_name] = rule
        # 否则，将这个rule添加到删除的列表中
        else:
            deleted_rules.append(rule)
            
    # 将字典转换为列表并返回
    return list(rule_dict.values()), deleted_rules



def delete_non_abnf_old(rulelist):
    # Step 1: Record all rulenames in a set.
    predefined_rulenames = {"_CONSTANT", "OCTET", "BIT", "HEXDIG", "CTL", "HTAB", "LWSP", "CR", "VCHAR", "DIGIT", 'WSP', 'DQUOTE', 'LF', 'SP', 'CRLF', 'CHAR', 'ALPHA',}
    defined_names = set(rule.split("=")[0].strip() for rule in rulelist) | predefined_rulenames
    
    # List to keep valid rules
    valid_rules = []
    # List to keep removed rules
    removed_rules = []

    # Step 2: Check each rule.
    for rule in rulelist:
        # Replace all quoted strings with _CONSTANT
        temp_rule = re.sub(r'"[^"]*"', "_CONSTANT", rule)

        # Remove the part after the semicolon.
        rule_no_comment = temp_rule.split(";", 1)[0]

        # Get the part between the first equals sign.
        parts = rule_no_comment.split("=", 1)
        part = parts[1].strip()

        # Extract rulenames
        # This regex looks for word characters that aren't inside double quotes.
        rulenames = re.findall(r'(?:(?<=\s)|(?<=^))(?:(?![\w-]*")[\w-]+)', part)

        # If any of the rulenames doesn't exist in defined_names, remove the rule.
        # But if the part contains "/" or "*", or any rulename contains "-", or "_CONSTANT" in part, keep the rule.
        is_undefined_rulename = all(rulename not in defined_names for rulename in rulenames)
        contains_slash_or_star = "/" in part or "*" in part
        contains_hyphen = any('-' in rulename for rulename in rulenames)
        contains_constant = "_CONSTANT" in part
        
        if is_undefined_rulename and not contains_slash_or_star and not contains_hyphen and not contains_constant:
            removed_rules.append(rule)
        else:
            valid_rules.append(rule)
    return valid_rules, removed_rules


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


    parser = abnf.grammars.rfc5234.Rule('rule')
    node = parser.parse_all(rule)
    name_list = get_rulename_from_node(node)
    return name_list


def get_group(node):
    """Do a breadth-first search of the tree for addr-spec node.  If found, 
    return its value."""
    rulenames = []
    queue = [node]
    while queue:
        n, queue = queue[0], queue[1:]
        if n.name == 'group':
            rulenames.append(n.value)
        
        queue.extend(n.children)
    return rulenames

def get_group_names(rule):
    import re

    def extract_words_from_parentheses(text):
        # 使用正则表达式提取括号内的内容
        matches = re.findall(r'\((.*?)\)', text)
        if matches:
            words = matches[0].split()  # 分割单词
            return words  # 在每个单词两侧添加双引号并返回列表
        return []
    
    parser = abnf.grammars.rfc5234.Rule('rule')
    node = parser.parse_all(rule)
    group = get_group(node)
    if group:
        group_names = extract_words_from_parentheses(group[0])
        return group_names
    else:
        return []


def delete_non_abnf(rulelist):
    import abnf

    name_list_list = []
    defined_names = {"OCTET", "BIT", "HEXDIG", "CTL", "HTAB", "LWSP", "CR", "VCHAR", "DIGIT", 'WSP', 'DQUOTE', 'LF', 'SP', 'CRLF', 'CHAR', 'ALPHA',}
    
    # List to keep valid rules
    valid_rules = []
    # List to keep removed rules
    removed_rules = []
    
    for rule in rulelist:
        rule += "\n"
        rule = rule.replace("\n","\r\n")

        name_list = get_dependence_rulename(rule)
        defined_names.add(name_list[0])
        name_list_list.append(name_list[1:])
    
    for i, rule in enumerate(rulelist):
        rulenames = name_list_list[i]

        is_undefined_rulename = False
        if rulenames: # 如果右边有rulenmaes，且都未定义
            is_undefined_rulename = all(rulename not in defined_names for rulename in rulenames)
        
        contains_slash_or_star = "/" in rule or "*" in rule
        contains_hyphen = any('-' in rulename for rulename in rulenames)
        contains_constant = '"' in rule

        if is_undefined_rulename and not contains_slash_or_star and not contains_hyphen and not contains_constant:
            removed_rules.append(rule)
        else:
            valid_rules.append(rule)
    return valid_rules, removed_rules


            




if __name__ =="__main__":
    # 找到rulelist中没有定义的name，在字典中查找他们，如果在字典中，则将对应的rule添加到该list中
    input_folder = 'abnf/parse_out'
    output_folder = 'abnf/cross_def'

    data = []

    undefined_names = []
    undefined_nums = []
    rule_dict = get_def_dict("abnf/parse_out") # rulename:{'rule':'aaa = bbb','src':i}
    non_abnf_data = []


    os.makedirs("abnf/cross_def", exist_ok=True)

    txt_files = glob.glob(input_folder + "/*.txt")

    for file_path in tqdm(txt_files):
        match = re.search(r'rfc(\d+)\.txt', file_path)
        i = int(match.group(1)) if match else None
        out_path = f'{output_folder}/rfc{i}.txt'

        rulelist = read_rulelist(file_path)
        rulelist, removed = remove_duplicate(rulelist) # remove duplicate rules
        rulelist, non_abnf = delete_non_abnf(rulelist) 
        
        # get undefined names
        valid_names, invalid_names = check_names_definition_simple(rulelist) 
        
        # search undefined names in other rfc doc
        added_rules = []
        for name in invalid_names:
            if name in rule_dict:
                rule = rule_dict[name]['rule']
                added_rules.append(rule)
                # 记录csv 
                data.append((i,rule,rule_dict[name]['src']))

        
        # keep record of deleted rules
        for rule in non_abnf:
            non_abnf_data.append((i,rule))

        rulelist.extend(added_rules)
        write_list_txt(rulelist,out_path)


        names_and_rules, undefined_all  = get_undefined_names(rulelist,rule_dict)


        for t in names_and_rules:
            undefined_names.append((i,t[0],t[1],t[2]))

        undefined_nums.append((i,undefined_all,len(undefined_all)))



    with open('csv_files/non_abnf.csv', mode='w', newline='') as file:
        fieldnames = ['rfc_num', 'rule']
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        for row in non_abnf_data:
            writer.writerow(row)   
    
    with open('csv_files/add_cross_def.csv', mode='w', newline='') as file:
        fieldnames = ['rfc_num', 'added_rule',"src"]
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        for row in data:
            writer.writerow(row)    
    
    
    with open('csv_files/undef_name_and_rule.csv', mode='w', newline='') as file:
        fieldnames = ['rfc_num', 'rule',"undef_name","num"]
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        for row in undefined_names:
            writer.writerow(row)    
    
    with open('csv_files/undefined_all.csv', mode='w', newline='') as file:
        fieldnames = ['rfc_num', 'undefined_names',"num"]
        writer = csv.writer(file)
        writer.writerow(fieldnames)
        for row in undefined_nums:
            writer.writerow(row)   

                



