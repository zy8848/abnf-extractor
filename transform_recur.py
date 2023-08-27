

import rfc5234_extend
import abnf
from abnf.parser import Concatenation, Alternation, Repetition,Repeat

"""
Transform with these recursive cases:

E = T / T , E   ==> E = T *(, E) 

domains = node / node "." domains
==>
domains = node *("." node)


E = T * (, E) ==> E = T *(, T)  

uid-set         = (uniqueid / uid-range) *("," uid-set)
==>
uid-set         = (uniqueid / uid-range) *("," (uniqueid / uid-range))


"""


class OurRule(abnf.Rule):
    """Represent our ABNF rule list read from a file."""

    pass


def recur_check1(rule):
    # 检查规则的定义是否为 Alternation 对象
    if not isinstance(rule.definition, Alternation):
        return False

    # 检查 Alternation 对象是否有两个元素
    if len(rule.definition.parsers) != 2:
        return False

    # 检查第一个元素是否为 Concatenation 对象或者其他非递归元素
    if not isinstance(rule.definition.parsers[0], abnf.Rule):
        return False

    # 检查第二个元素是否为 Concatenation 对象
    if not isinstance(rule.definition.parsers[1], Concatenation):
        return False

    # 检查 Concatenation 对象的元素是否包含一个指向规则自身的引用和一个 Repetition 对象
    last_parser = rule.definition.parsers[1].parsers[-1]

    if isinstance(last_parser, abnf.Rule) and last_parser.name == rule.name:
        return True

    return False

    
def recur_check2(rule):
    # 检查规则的定义是否为 Concatenation 对象
    if not isinstance(rule.definition, Concatenation):
        return False

    # 检查 Concatenation 对象是否有两个元素
    if len(rule.definition.parsers) != 2:
        return False

    # 检查第一个元素是否为非递归元素
    # if isinstance(rule.definition.parsers[0], abnf.Rule):
    #     return False

    # 检查第二个元素是否为 Repetition 对象
    if not isinstance(rule.definition.parsers[1], Repetition):
        return False

    # 检查 Repetition 对象的元素是否是一个指向规则自身的引用
    if rule.definition.parsers[1].element.parsers[-1].name == rule.name:
        return True

    return False



def recur_transform1(node):
    """
    E = T / T , E   ==> E = T *(, E) 

    domains = node / node "." domains
    ==>
    domains = node *("." node)
    """


    E = node.children[0].value
    rule_definition = node.children[2]


    # 获取原规则的第一个元素和第二个元素
    T = rule_definition.children[0].children[0].children[0].value

    right_part = rule_definition.children[0].children[-1] # T , E
    

    if right_part.value[0]=='(' and right_part.value[-1]==')': # '(' means group , e.g. (option ";" options)
        while right_part.name != 'group':
            right_part = right_part.children[0]

        # get rid of bracket in the first and last position, get the alternation part of group
        # group          =  "(" *c-wsp alternation *c-wsp ")" 
        for child in right_part.children:
            if child.name == 'alternation':
                alternation_part = child 
                break
        
        right_part = alternation_part.children[0]# get concatenation part


        # while right_part.name != 'concatenation': # get element in the middle
        #      right_part = right_part.children[0]

    assert right_part.name == 'concatenation'
    repetition_str = ""
    for part in right_part.children:
        if part.value == T :
            continue

        if part.value == E: # substitute E with T
            part_str = T
        else:
            part_str = part.value
        repetition_str += part_str



    # 生成新的规则字符串
    new_rule_str = f"{E} = {T} *({repetition_str})"


    return new_rule_str

def recur_transform2(node):
    """
    E = T * (, E) ==> E = T *(, T)  
    e.g.
    uid-set         = (uniqueid / uid-range) *("," uid-set)
    ==>
    uid-set         = (uniqueid / uid-range) *("," (uniqueid / uid-range))

    """

    def get_charval_node(node):
        """Do a breadth-first search of the tree for addr-spec node.  If found, 
        return its value."""
        vals = []
        queue = [node]
        while queue:
            n, queue = queue[0], queue[1:]
            if n.name == 'char-val' and n.value not in ['(',')']:
                val = n.value
                break
            queue.extend(n.children)
        return val

    # 使用 Node 对象的 value 属性获取规则的名称和定义
    rule_name = node.children[0].value
    rule_definition = node.children[2]


    # 获取原规则的第一个元素和第二个元素
    first_element = rule_definition.children[0].children[0].children[0].value
    charval = get_charval_node(rule_definition.children[0].children[0])


    # 生成新的规则字符串
    new_rule_str = f"{rule_name} = {first_element} *({charval} {first_element})"

    return new_rule_str




if __name__ == "__main__":
    import csv
    
    with open('csv_files/simple_recur.csv', 'r') as f:
        reader = csv.reader(f)
        next(reader)
        data_to_write = []  # 创建一个新的列表来存储数据
        for row in reader:
            rule_str = row[1]

            rule_str += '\n'
            rule_str = rule_str.replace('\n','\r\n')
            parse_tree, start = abnf.parser.ABNFGrammarRule("rule").parse(rule_str, start = 0)
            visitor = abnf.parser.ABNFGrammarNodeVisitor(rule_cls=OurRule)
            rule = visitor.visit(parse_tree)

            if recur_check1(rule):
                new_rule = recur_transform1(parse_tree)
            elif recur_check2(rule):
                new_rule = recur_transform2(parse_tree)
            else:
                new_rule = ''
            
            if new_rule != '':
                row.append(new_rule)
            data_to_write.append(row)  # 将数据添加到新的列表中
        
        with open('csv_files/simple_recur_update.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['rfc_num', 'rule', 'transformed_rule'])            
            writer.writerows(data_to_write)  # 使用新的列表来写入数据



