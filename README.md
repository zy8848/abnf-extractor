# ABNF Extractor
This is the repo for extracting ABNF rules from RFC documents. The flowchart for the extraction process is below.

1. Download all RFC doc from website and save it (download.py)
2. Using regexp to extract what looks like abnf in RFC doc (reg_matching.py)
3. Preprcess the rules extracted in step 2 (preprocess.py)
4. Parse every rules and discard the rule that cannot be parsed (parse.py).
5. Add cross definition in every document. (cross_def.py)

![alt text](img/flowchart.jpg)