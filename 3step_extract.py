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


    for i,rule in enumerate(rules):
        rules[i] = rule[0]

    from abnf.grammars import rfc5234


    parser = rfc5234.Rule('rule')
    list_parser = rfc5234.Rule('rulelist')
    valid_rules = []
    invalid_rules = []
    for rule in rules:
        rule = rule.replace("\n","\r\n")
        try:
            node = parser.parse_all(rule)
            node1 = list_parser.parse_all(rule)
            valid_rules.append(rule)
        except:
            invalid_rules.append(rule)

    
    # if valid_rules:
    #     with open(f'parse_out/rfc{rfc_num}.txt', 'w') as f:
    #         for rule in valid_rules:
    #             f.write(rule + '\n')
    # if invalid_rules:
    #     with open(f'parse_invalid/rfc{rfc_num}.txt', 'w') as f:
    #         for rule in invalid_rules:
    #             f.write(rule + '\n')
    
    valid_names, invalid_names = check_names_definition(valid_rules)
    num_names = len(valid_names) + len(invalid_names)
    return len(valid_rules), num_names, len(invalid_names), invalid_names
            






def check_names_definition(rulelist): # get valid names and invalid names
    # parse每一个rule，
    # 把所有等号左边的记录下来，
    # 检查每个等号右边的name，如果不是终止符，则判断其是否在左边出现过，如果没出现过，则加入invalid name
    import abnf

    class OurRule(abnf.Rule):
        pass

    text = "".join(rulelist)
    #text = text.replace("0x","%x")
    node = abnf.parser.ABNFGrammarRule("rulelist").parse_all(text)
    visitor = abnf.parser.ABNFGrammarNodeVisitor(rule_cls=OurRule)
    visitor.visit(node)

    invalid_name = []
    valid_name = []
    for rule in OurRule.rules():  # type: ignore
        if not hasattr(rule, "definition"):
            invalid_name.append(rule.name)
        else:
            valid_name.append(rule.name)

    return valid_name, invalid_name


def check_names_definition_simple(rulelist): # get valid names and invalid names
    # parse每一个rule，
    # 把所有等号左边的记录下来，
    # 检查每个等号右边的name，如果不是终止符，则判断其是否在左边出现过，如果没出现过，则加入invalid name
    
    import abnf
    valid_name = set()
    invalid_name = set()
    abnf_rules = [
        "ALPHA", "BIT", "CHAR", "CR", "CRLF", "CTL", "DIGIT", "DQUOTE", "HEXDIG",
        "HTAB", "LF", "OCTET", "SP", "VCHAR", "WSP", "element", "ALTERNATIVE",
        "CONCATENATION", "OPTIONAL", "REPEAT"
    ]


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







if __name__ == "__main__":
    import os
    import csv

    extract_abnf(733)
    # rows = []
    # for i in range(1,9999):
    #     print(i)
    #     if os.path.exists(f'input_abnf/rfc{i}.txt'):
    #         try:
    #             row = [i]
    #             row.extend(extract_abnf(i))
    #             rows.append(row)

    #         except Exception as e:
    #             print(f"rfc{i}处理错误")
    #             print(e)
    

    with open('result.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['rfc_No','valid_rules_count', 'num_names', 'invalid_names_count', 'invalid_names'])
    
    with open('result.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(rows)

    

