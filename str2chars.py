import sys
o = 'char msg[] = {'
o += ','.join(map(repr,sys.argv[1].replace('\\n','\n')))
o += ', 0x00'
o = o.replace("'\\n'",'0x0a')
o += '};'
print(o)

