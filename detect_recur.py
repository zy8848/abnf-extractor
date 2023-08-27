import re
from tqdm import tqdm
import glob
import os
import csv
from write_names import read_file
from data_utils import read_rulelist,write_list_txt


"""
Scirpt to detect the linear recursion rule and write it to csv
"""
def parse_abnf(file_path):
    rules = {}
    with open(file_path, 'r') as f:
        for line in f.readlines():
            tokens = line.strip().split(',')
            rule_name = tokens[0]
            referenced_rules = set(tokens[1:])
            rules[rule_name] = referenced_rules
    return rules

def dfs(rule, ruleset, visited, path=[]):
    if rule not in ruleset:
        # print(f"Incomplete path: {' -> '.join(path + [rule])}")
        return False
    if rule in visited:
        return True

    visited.add(rule)
    path.append(rule)
    for dependency in ruleset[rule]:
        if not dfs(dependency, ruleset, visited, path):
            return False
    path.pop()
    return True

def is_complete(ruleset):
    for rule in ruleset:
        if not dfs(rule, ruleset, set(), []):
            return False
    return True

def is_ruleset_complete(ruleset):
    defined_rules = set(ruleset.keys())
    for dependencies in ruleset.values():
        for dependency in dependencies:
            if dependency not in defined_rules:
                return False
    return True

def make_complete(graph,rulelist):
    incomplete_rules = set()
    for rulename in graph:
        if not dfs(rulename, graph, set(), []):
            incomplete_rules.add(rulename)

    for rulename in incomplete_rules:
        del graph[rulename]

    new_rulelist = []
    for rule in rulelist:
        rulename = rule.split("=")[0].strip()
        if rulename in graph:
            new_rulelist.append(rule)

    return new_rulelist,graph

# def save_to_file(ruleset, output_path):
#     with open(output_path, 'w') as f:
#         for rule, dependencies in ruleset.items():
#             f.write(f"{rule},{','.join(dependencies)}\n")





if __name__ == "__main__":
    input_folder = "abnf/cross_def"
    name_folder = 'abnf/names'
    txt_files = glob.glob(input_folder + "/*.txt")

    all_rule = set()
    csv_data = []
    for file_path in tqdm(txt_files):
        match = re.search(r'rfc(\d+)\.txt', file_path)
        i = int(match.group(1)) if match else None

        rulelist = read_rulelist(file_path)
        namelist = read_file(f"{name_folder}/rfc{i}.txt")
        assert len(rulelist) == len(namelist)
        
        for idx in range(len(rulelist)):

            rule = rulelist[idx]
            names = namelist[idx]
        
            for rulename in names[1:]:
                if rulename == names[0]:
                    csv_data.append((i,rule))
                    break
    with open("csv_files/simple_recur.csv", 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["RFC Number", "Rule"])  # Writing the headers
        writer.writerows(csv_data)
    
        
    
