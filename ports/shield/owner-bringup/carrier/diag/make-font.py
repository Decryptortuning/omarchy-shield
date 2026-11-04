#!/usr/bin/env python3
"""Generate font8x16.h for fbstatus.c from a Linux tree's lib/fonts/font_8x16.c.
Usage: make-font.py <linux>/lib/fonts/font_8x16.c font8x16.h"""
import re, sys
s = re.sub(r'/\*.*?\*/', '', open(sys.argv[1]).read(), flags=re.S)
body = s[s.index('fontdata_8x16'):]
body = body[body.index('{') + 1:].split('};')[0]
vals = re.findall(r'0x[0-9a-fA-F]{2}\b', body)
assert len(vals) == 4096, len(vals)
open(sys.argv[2], 'w').write('static const unsigned char font8x16[4096]={' + ','.join(vals) + '};\n')
