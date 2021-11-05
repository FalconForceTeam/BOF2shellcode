import sys
def hash_djb2(s):
    hash = 5381
    for x in s:
        hash = (( hash << 5) + hash) + ord(x)
        hash = hash & 0xFFFFFFFF
    return hash

h = hash_djb2(sys.argv[1])
print(hex(h))
