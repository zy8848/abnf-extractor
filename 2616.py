import re
from abnf.grammars import rfc5234
def abnf_transform(abnf_rule):
    def expand_repeats(match):
        min_count, max_count, element = match.groups()
        min_count = int(min_count) if min_count else 0
        max_count = int(max_count) if max_count else float("inf")
        if min_count>100:
            print(f"Skip, because it looks like not a abnf: {match.group(0)}")
            return match.group(0)

        if max_count == float('inf'):
            repetitions = [element for _ in range(min_count)]
            # return "(" + " ".join(repetitions) + " *(" + " " + element + "))"
            return  " ".join(repetitions) + " *(" + " " + element + ")"
        else:
            # 暂时不考虑这种情况
            print("cannot convert")
            return match.group(0)
            
    
    transformed_abnf = re.sub(r'(\d*)#(\d*)\(([^)]+)\)', expand_repeats, abnf_rule)
    transformed_abnf = re.sub(r'(\d*)#(\d*)([A-Za-z][A-Za-z0-9-]*)', expand_repeats, transformed_abnf)
    return transformed_abnf

# input_abnf = "Accept-Language = #( language-range [ weight ] )\r\n"

input_abnf = """
optional-field  =
               "To"         ":" #address
            /  "cc"         ":" #address
            /  "bcc"        ":" #address    ; Blind carbon
            /  "Subject"    ":" *text
            /  "Comments"   ":" *text
            /  "Message-ID" ":" mach-id     ; Only one allowed
            /  "In-Reply-To"":" #(phrase / mach-id)
            /  "References" ":" #(phrase / mach-id)
            /  "Keywords"   ":" #phrase
            /  extension-field              ; To be defined in
                                            ;  supplemental
                                            ;  specifications
            /  user-defined-field           ; Must have unique
                                            ;  field-name & may
                                            ;  be pre-empted                                      

"""

input_abnf2 = """
optional-field  =
               "To"         ":" *address
            /  "cc"         ":" *address
            /  "bcc"        ":" *address    ; Blind carbon
            /  "Subject"    ":" *text
            /  "Comments"   ":" *text
            /  "Message-ID" ":" mach-id     ; Only one allowed
            /  "In-Reply-To"":" *( phrase / mach-id)
            /  "References" ":" *( phrase / mach-id)
            /  "Keywords"   ":" *phrase
            /  extension-field              ; To be defined in
                                            ;  supplemental
                                            ;  specifications
            /  user-defined-field           ; Must have unique
                                            ;  field-name & may
                                            ;  be pre-empted                                      

"""

import os
import csv
data = []
for i in range(1,9999):
    if i in [8633]:
        print(f"skip {i}")
        continue
    if os.path.exists(f'parse_invalid/rfc{i}.txt'):
        print(i)
        with open(f"parse_invalid/rfc{i}.txt", 'r') as f:
            file_str = f.read()
            rules = file_str.split('\n\n')


        ori = []
        transformed = []
        for rule in rules:
            rule += "\n"
            rule = rule.replace("\n","\r\n")
            if '#' in rule:
                new_rule = abnf_transform(rule)
                if new_rule != rule:
                    ori.append(rule)
                    transformed.append(new_rule)
                    
        for idx in range(len(ori)):
            data.append((i,ori[idx].strip(),transformed[idx].strip()))



with open('data.csv', mode='w', newline='') as file:
    fieldnames = ['rfc_num', 'origin', 'transformed']
    writer = csv.writer(file)
    writer.writerow(fieldnames)
    for row in data:
        writer.writerow(row)    







# parser = rfc5234.Rule('rule')
# l1 = []
# l2 = []
# for rule in rules:
#     rule += "\n"
#     rule = rule.replace("\n","\r\n")
#     try:
#         parser.parse_all(rule)
#         l1.append(rule)
#     except:
#         l2.append(rule)


# src = 'route       =  1#("@" domain) ":"           ; path-relative\r\n'
# src1 = 'group       =  phrase ":" [#mailbox] ";"\r\n'
# output_abnf = abnf_transform(src1)
# parser.parse_all(output_abnf)
# print(output_abnf)



print("1")
