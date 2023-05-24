from abnf.grammars import rfc5322
from abnf.grammars import rfc5234

import io








file_name = "rfc5234.txt"
ABNF_PATH = f"input_abnf/{file_name}"
OUTPUT_PATH = f"output/{file_name}"
with io.open(ABNF_PATH, 'rt', newline='') as f:
    lines = f.readlines()

paras = []
i = j = 0
while i < len(lines):
    if lines[i] in ['\r\n' ,'\x0c\r\n']:
        i += 1
    else:
        j = i
        while lines[j+1] not in ['\r\n' ,'\x0c\r\n']:
            j += 1
        
        paras.append("".join(lines[i:j+1]).lstrip())
        i = j + 1
        

parser = rfc5234.Rule('rule')


valid_abnf = []
others = []



for para in paras:

    try:
        node = parser.parse_all(para)
        valid_abnf.append(para)
    except:
        if "=" in para:
            others.append(para)


# remove duplicate
exp_dict = {}
for exp in valid_abnf:
    rule_name = exp.split("=")[0].strip()
    if rule_name in exp_dict:
        print(f"remove: {exp_dict[rule_name]}")
        print(f"New: {exp}")
    exp_dict[rule_name] = exp





with open(OUTPUT_PATH, "w") as file:
    # Loop through the list and write each item to the file on its own line
    for item in exp_dict.values():
        file.write(item)






# remove rules without definition

# import abnf
# from abnf.parser import ABNFGrammarNodeVisitor,Node,Rule,Parser,Alternation
# class OurRule(abnf.Rule):
#     """Represent our ABNF rule list read from a file."""

#     pass
# class myVisitor(ABNFGrammarNodeVisitor):
#     def __init__(
#         self,*args, **kwargs
#     ):
#         super().__init__(*args, **kwargs)
    
#     def visit_rule(self, node: Node):
#         """Visits a rule node, returning a Rule object."""
#         rule: Rule
#         defined_as: str
#         elements: Parser
#         try:
#             rule, defined_as, elements = filter(None, map(self.visit, node.children))
#             # this assertion tells mypy that rule should actually be an object. Without, mypy
#             # returns 'error: <nothing> has no attribute "definition"'
#             assert rule
#             rule.definition = (
#                 elements if defined_as == "=" else Alternation(rule.definition, elements)
#             )
#             return rule
#         except:
#             return None


# parser = rfc5234.Rule('rulelist')
# abnf_str = "".join(valid_abnf)
# node = parser.parse_all(abnf_str)


# visitor = myVisitor(rule_cls=OurRule)
# visitor.visit(node)

# non_def_list = []
# for rule in OurRule.rules():  # type: ignore
#     if not hasattr(rule, "definition"):
#         print(f"Unexpected rule without a definition: {rule.name!r}")
#         non_def_list.append(rule.name)

