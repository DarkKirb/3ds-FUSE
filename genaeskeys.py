#!/usr/bin/env python3
import struct
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
boot9=open("boot9.bin","rb")
f=boot9
if True:
    def getKey(no,dic):
        dic[no]=f.read(16)
        f.seek(-16,1)
    def getKeyloop(no,dic):
        for i in range(4):
            getKey(no+i,dic)
        f.read(16)
    def getKeyloop_increase(no,dic):
        for i in range(4):
            getKey(no+i,dic)
            f.read(16)
    f.seek(0xd860) #Beginning of keyarea
    _3fgendata=f.read(36)
    keyX={}
    keyY={}
    normals={}
    f.seek(0xd9d0)
    getKeyloop(0x2C,keyX)
    getKeyloop(0x30,keyX)
    getKeyloop(0x34,keyX)
    getKeyloop(0x38,keyX)
    getKeyloop_increase(0x3C,keyX)
    getKeyloop_increase(0x4,keyY)
    getKeyloop_increase(0x8,keyY)
    getKeyloop(0xC,normals)
    getKeyloop(0x10,normals)
    getKeyloop_increase(0x14,normals)
    getKeyloop(0x18,normals)
    getKeyloop(0x1C,normals)
    getKeyloop(0x20,normals)
    getKeyloop(0x24,normals)
    f.seek(-16,1)
    getKeyloop_increase(0x28,normals)
    getKeyloop(0x2C,normals)
    getKeyloop(0x30,normals)
    getKeyloop(0x34,normals)
    getKeyloop(0x38,normals)
    f.seek(-16,1)
    getKeyloop_increase(0x3C,normals)
    f.seek(0xD6E0)
    otpkey=f.read(16)
    otpiv=f.read(16)
    f.seek(0xD860)
from Crypto.Cipher import AES
with open("otp.bin","rb") as f:
    cipher=AES.new(otpkey, AES.MODE_CBC, otpiv)
    otp=cipher.decrypt(f.read())
import hashlib
conunique=otp[:28]+_3fgendata
conunique_hash=hashlib.sha256(conunique).digest()
del normals[0x3F]
keyX[0x3F]=conunique_hash[:16]
keyY[0x3F]=conunique_hash[16:]
def genkeys(size=0x40):
    boot9.read(36)
    aesiv=boot9.read(16)
    conunique_input=boot9.read(64)
    boot9.seek(-64,1)
    boot9.read(size)
    cipher=AES.new(scramble(keyX[0x3F],keyY[0x3F]),AES.MODE_CBC,aesiv)
    return cipher.encrypt(conunique_input)
def getKey(dic,no,conunique,off):
    dic[no]=conunique[off:off+16]
def getKeyloop(dic,no,conunique,off):
    for i in range(4):
        getKey(dic,no+i,conunique,off)
def getKeyloop_increase(dic,no,conunique,off):
    for i in range(4):
        getKey(dic,no+i,conunique,off+16*i)
conunique=genkeys()
getKeyloop(keyX,4,conunique,0)
getKeyloop(keyX,8,conunique,16)
getKeyloop(keyX,0xC,conunique,32)
getKey(keyX,0x10,conunique,48)

conunique=genkeys(16)
getKeyloop_increase(keyX,0x14,conunique,0)

conunique=genkeys()

getKeyloop(keyX,0x18,conunique,0)
getKeyloop(keyX,0x1C,conunique,16)
getKeyloop(keyX,0x20,conunique,32)
getKey(keyX,0x24,conunique,48)

conunique=genkeys(16)
getKeyloop_increase(keyX,0x28,conunique,0)

#Generate normal keys
for kx in keyX.keys():
    if kx in keyY:
        normals[kx]=scramble(keyX[kx],keyY[kx])
n=normals
normals={}
for kn in n.keys():
    if ((kn in keyX) and (kn in keyY)) or ((kn not in keyX) and (kn not in keyY)):
        normals[kn]=n[kn] #only keep normal keys that are in keyX,keyY pairs, or are just normal keys.
with open("aeskeydb.bin","ab") as f:
    for kx in keyX.keys():
        f.write(struct.pack("<B",kx))
        f.write(b'X')
        f.write(bytes(14))
        f.write(keyX[kx])
    for ky in keyY.keys():
        f.write(struct.pack("<B",ky))
        f.write(b'Y')
        f.write(bytes(14))
        f.write(keyY[ky])
    for kn in normals.keys():
        f.write(struct.pack("<B",kn))
        f.write(b'N')
        f.write(bytes(14))
        f.write(normals[kn])
