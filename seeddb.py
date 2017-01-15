import struct
def binfilegen(f,s):
    x=f.read(s)
    while len(x) == s:
        yield x
        x=f.read(s)
def seedwalk():
    f = open("seeddb.bin","rb")
    f.read(16)
    for s in binfilegen(f,32):
        tid=struct.unpack("<Q",s[:8])[0]
        seed=s[8:24]
        yield (tid,seed)

def getSeed(tid):
    for t,s in seedwalk():
        if tid==t:
            return s
    return None
