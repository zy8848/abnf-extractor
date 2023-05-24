import os
import csv
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
                        result_dict[rule_name] = f'rfc{rfc_num}'
    return result_dict

rule_dict = get_def_dict("parse_out")



with open('csv_files/output_file.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    fieldnames = reader.fieldnames + ['cross_def', '# cross_def']
    rows = []
    for row in reader:
        invalid_names = row['invalid_names']
        if invalid_names != 'set()':
            invalid_names_set = eval(invalid_names)
            crossname_and_src = []
            for name in invalid_names_set:
                if name in rule_dict:
                    crossname_and_src.append(f"{name}:{rule_dict[name]}")

            row['cross_def'] = ",".join(crossname_and_src)
            row['# cross_def'] = len(crossname_and_src)
        else:
            row['cross_def'] = ''
            row['# cross_def'] = 0
        rows.append(row)

with open('csv_files/output_file_cross.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)





# def add_rules(rule_dict,csv_path) # 输出csv 