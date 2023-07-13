
import re
import glob
import os
import shutil
from tqdm import tqdm
import fileinput

def extract_abnf(input_file,output_file):
  
    rules = []
    rule_lines = []
    rule_indent = None

    with open(input_file, "r", errors='replace') as f_in:
        # lines = filter(lambda line: line.strip(), f_in.readlines())
        for line in f_in:
            # 判断当前行是否为ABNF规则的第一行
            match = re.match(r"\s*([a-zA-Z0-9-]+)\s*=[^\n]*\n", line)
            if match:
                # 如果当前行不是第一个ABNF规则，则将前一个ABNF规则加入到rules列表中
                if rule_lines:
                    rules.append(rule_lines)
                    rule_lines = []
                # 记录当前ABNF规则的缩进量和第一行
                rule_indent = len(line) - len(line.lstrip())
                rule_lines.append(line.lstrip())
            elif line.strip(): # 不match第一行，两种可能：一种属于当前abnf，或者是普通文字
                if rule_lines: # 不匹配时，只关注buffer的rule_lines还未结束时
                    line_indent = len(line) - len(line.lstrip())
                    if line_indent <= rule_indent:
                        # 缩进更小或相等，则是无关文字，(不可能是新abnf，因为未匹配)
                        # rule_lines.append(line)
                        rules.append(rule_lines)
                        rule_lines = []
                    else:
                        # 缩进更大，则认为当前行属于当前ABNF规则
                        rule_lines[-1] += line[rule_indent:]
            elif not line.strip() and rule_lines:
                # 如果读取到空行，则将已经读取到的ABNF规则加入到rules列表中
                rules.append(rule_lines)
                rule_lines = []

    # 处理最后一个ABNF规则
    if rule_lines:
        rules.append(rule_lines)

    
    if rules:
        with open(output_file, "w") as f_out:
            for i, rule_lines in enumerate(rules):
                if i > 0:
                    # 每个ABNF规则之间空一行
                    f_out.write("\n")
                for l in rule_lines:
                    f_out.write(l)
            if rules:
                # 最后一个ABNF规则之后不需要再空一行
                f_out.write("\n")
    
    if rules:
        return True
    else: 
        return False



def main():
    source_directory = "abnf/rfc_docs/"
    output_directory = "abnf/regexp_out/"

    # 创建输出目录（如果不存在）
    os.makedirs(output_directory, exist_ok=True)

    # 获取目录下所有的 txt 文件路径
    txt_files = glob.glob(source_directory + "*.txt")
    num_files = 0

    print("Start regexp matching")
    for txt_file in tqdm(txt_files):
        filename = os.path.basename(txt_file)
        output_file = os.path.join(output_directory, filename)


        # 调用 extract_abnf 函数处理输入文件并写入输出文件
        contain_rules = extract_abnf(txt_file, output_file)
        if contain_rules:
            num_files += 1

    print(f"{len(txt_files)} files have been processed, {num_files} files contain abnf rules")





if __name__ == '__main__':
    main()