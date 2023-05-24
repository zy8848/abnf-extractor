
import re

def extract_abnf(rfc_num,write_output = True):
    input_file = f"rfc_docs/rfc{rfc_num}.txt"
  
    rules = []
    rule_lines = []
    rule_indent = None

    with open(input_file, "r") as f_in:
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


    
    output_file = f"regexp_output/rfc{rfc_num}.txt"
    if write_output and rules:
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