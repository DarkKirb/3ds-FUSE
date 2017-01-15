import struct
def binfilegen(f,s):
    x=f.read(s)
    while len(x) == s:
        yield x
        x=f.read(s)
def aeskeywalk(fname):
    f=open(fname,"rb")
    for k in binfilegen(f,32):
        slot,xyn=struct.unpack("<BB",k[:2])
        t=0
        if xyn == 0x59:
            t=2
        elif xyn == 0x58:
            t=1
        yield (slot,t,k[16:])

def getKey(no):
    """
    Returns a tuple:
    [normal, keyX, keyY]
    None if unknown
    """
    key=[None, None, None]
    for s,t,k in aeskeywalk("aeskeydb.bin"):
        if s == no:
            if key[t] == None:
                key[t]=k
    return key
