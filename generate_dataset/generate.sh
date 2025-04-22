#!/bin/bash

cwe_numbers=(179 915 1333 200 367 770 295 77 601 22 74 78 120 281 327 352 79 94 502 863 338 862 918 611 400 732 347 95)

for cwe in "${cwe_numbers[@]}"
do
    echo "Processing CWE-$cwe"
    python generate.py --template cve_test_template.py --full_code "data/cwe-$cwe.py" --output_json "data/cwe-$cwe.json"
done

echo "All CWE tests completed."