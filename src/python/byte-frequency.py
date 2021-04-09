# -*- coding: utf-8 -*-
"""

This program aims to find the ASCII values not in used by the content of a given ruleset

"""

import matplotlib.pyplot as plt
import sys
# Customize matplotlib

vals = {}

v_sum = 0

with open(sys.argv[1]) as f:
    for v in [line for line in f]:
        if len(v.strip()):
            if v.strip()[0] != "#":
                for l in v.strip().split(";"):
                    if l.split(":")[0].strip() == "content":
                        cnt = str(l.split(":")[1]).strip()
                        end = len(cnt)
                        j = 0
                        if cnt[j] == "!":
                            j += 1
                        cnt.strip()
                        if cnt[j] == "\"":
                            j += 1
                        cnt.strip()
                        if cnt[-1] == "\"":
                            end -= 1
                        while j < end:
                            c = cnt[j]
                            if c == "|":
                                j_p = cnt.find("|", j+1)
                                if j_p > 0:
                                    try:
                                        for c in bytearray.fromhex(cnt[j+1:j_p].replace("|", "")).decode('latin1'):
                                            if ord(c) not in vals:
                                                vals.update({ord(c): 1})
                                                v_sum+=1
                                            else:
                                                vals[ord(c)] += 1
                                                v_sum+=1
                                        j = j_p+1
                                    except Exception:
                                        break
                            else:
                                if ord(c) not in vals:
                                    vals.update({ord(c): 1})
                                    v_sum+=1
                                else:
                                    vals[ord(c)] += 1
                                    v_sum+=1
                                j += 1


for x,y in vals.items():
    vals[x]=float(y/v_sum)

vals = dict(sorted(vals.items(), key=lambda item: item[0]))

plt.bar(list(vals.keys()), vals.values(), color='darkorchid')
plt.title(sys.argv[1])
plt.xlabel("Byte")
plt.ylabel("Byte frequency")
plt.savefig("byte-frequency.svg")
