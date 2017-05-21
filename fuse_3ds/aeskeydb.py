import struct
from Crypto.Cipher import AES
from Crypto.Util import Counter
from os import path
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
    for s,t,k in aeskeywalk(path.join(path.expanduser("~"),"aeskeydb.bin")):
        if s == no:
            if key[t] == None:
                key[t]=k
    return key
def scramble(keyX,keyY):
    def asint128(a):
        if a < 0:
            raise ValueError("Must be positive")
        return a & ((2**128)-1)
    rotate=lambda c,v: (asint128(c<<v)|asint128(c>>128-v))
    keyX=int.from_bytes(keyX,"big")
    keyY=int.from_bytes(keyY,"big")
    kn = rotate(asint128((rotate(keyX,2)^keyY)+0x1FF9E9AAC5FE0408024591DC5D52768A),87)
    return kn.to_bytes(16,"big")
class NoBugCTR:
    def __init__(self, iv):
        self.ctr=int.from_bytes(iv,"big")
    def __call__(self, *kargs, **kwargs):
        iv=self.ctr.to_bytes(16,"big")
        self.ctr+=1
        if self.ctr == 2**128:
            self.ctr=0
        return iv
    def __iter__(self):
        return self
    def __next__(self):
        return self()
def getCipher(keyslot, iv, CBC=False, keyY=None):
    key=getKey(keyslot)[0]
    if keyY != None:
        keyX=getKey(keyslot)[1]
        if keyX == None:
            raise ValueError("Unknown KeyX for crypto")
        key=scramble(keyX, keyY)
    if key == None:
        raise ValueError("Unknown Key!")
    if CBC:
        return AES.new(key, AES.MODE_CBC, iv)
    cipher=AES.new(key, AES.MODE_CTR, counter=Counter.new(128,allow_wraparound=True,initial_value=int.from_bytes(iv,"big")))
    return cipher
