def write_list_txt(rulelist, file_path):
    with open(file_path, "w") as f_out:
        for i, rule_lines in enumerate(rulelist):
            if i > 0:
                # 每个ABNF规则之间空一行
                if rule_lines.endswith("\n"):
                    f_out.write("\n")
                else:
                    f_out.write("\n\n")
            for l in rule_lines:
                f_out.write(l)
        if rulelist:
            # 最后一个ABNF规则之后不需要再空一行
            f_out.write("\n")


def read_rulelist(file_path):
    with open(file_path, 'r') as f:
        file_str = f.read()
        rules = file_str.split('\n\n')
    if '' in rules:
        rules.remove('')
    return rules
