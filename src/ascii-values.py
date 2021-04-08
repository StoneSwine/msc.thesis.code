# -*- coding: utf-8 -*-
"""

This program aims to find the ASCII values not in used by the content of a given ruleset

"""

import matplotlib.pyplot as plt
import sys
# Customize matplotlib

vals = {}

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
                            j+=1
                        cnt.strip()
                        if cnt[j] == "\"":
                            j+=1
                        cnt.strip()
                        if cnt[-1] == "\"":
                            end-=1
                        while j < end:
                            c = cnt[j]
                            if c == "|":
                                j_p = cnt.find("|",j+1)
                                if j_p > 0:
                                    for c in bytearray.fromhex(cnt[j+1:j_p].replace("|", "")).decode('latin1'):
                                        if c not in vals:
                                            vals.update({c:1})
                                        else:
                                            vals[c] += 1
                                    j=j_p+1
                            else:
                                if c not in vals:
                                    vals.update({c:1})
                                else:
                                    vals[c] += 1
                                j += 1

print("Decimal values of ASCII not used by the rules:")
for x in range(128):
    if chr(x) not in vals:
        print(" ", x)

vals = dict(sorted(vals.items(), key=lambda item: item[1]))

plt.bar(list(vals.keys()), vals.values(), color='g')
plt.show()
