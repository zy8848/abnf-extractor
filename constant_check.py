import csv
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




with open('csv_files/result.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    fieldnames = reader.fieldnames + ['removed constant name', 'removed constant count']
    rows = []
    for row in reader:
        invalid_names = row['invalid_names']
        if invalid_names != 'set()':
            invalid_names_set = eval(invalid_names)
            removed_const_name = set()
            for name in invalid_names_set:
                if is_constant(name):
                    removed_const_name.add(name)
            row['removed constant name'] = str(removed_const_name)
            row['removed constant count'] = len(removed_const_name)
        else:
            row['removed constant name'] = ''
            row['removed constant count'] = ''
        rows.append(row)


# 写入CSV文件
with open('output_file.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)