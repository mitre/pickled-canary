# Copyright (C) 2025 The MITRE Corporation All Rights Reserved

import csv
import pprint

prefix = '..\\..\\..\\Documents\\paterns\\libcurl\\'

version_map = {}
with open("libcurl_bin_versions.csv", 'r', encoding='utf-8-sig') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        path = (row[0]+row[1]).replace("/", "\\")
        version_map[path] = row[2]

pprint.pprint(version_map)

with open('results_with_version.csv', 'w', newline="", encoding='utf-8-sig') as csvout:
    writer = csv.writer(csvout)
    with open("results.csv", "r", encoding='utf-8-sig') as csvfile:
        reader = csv.reader(csvfile)
        headers = next(reader)
        writer.writerow(headers + ["version"])
        for row in reader:
            writer.writerow(row + [version_map[row[1][len(prefix):]]])
