import struct
from . import aeskeydb
class Ticket:
    def __init__(self, f):
        sigtype=struct.unpack(">I",f.read(4))[0]-0x10000
        skip=[0x23C,0x13C,0x7C,0x23C,0x13C,0x7C]
        f.read(skip[sigtype])
        self.issuer=f.read(0x40)
        self.pubkey=f.read(0x3C)
        self.version,self.caCrlVersion,self.signerCrlVersion=struct.unpack("<BBB",f.read(3))
        self.titlekey=f.read(0x10)
        self.enckey=bytes(self.titlekey)
        f.read(1)
        self.tickid,self.cid,self.tid,self.tikTitleVersion,self.licenseType,self.keyYindex,self.eshopAID,self.audit=struct.unpack("<LILxxHxxxxxxxBBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxIxB",f.read(73))
        f.read(0x42)
        self.limits=f.read(0x40)
        self.contentIndex=f.read(0xAC)
        self.encrypted=self.titlekey != b'\xFF'*16
    def decryptTitleKey(self,tid):
        if self.encrypted:
            #Decrypt title key
            iv=tid.to_bytes(8, byteorder='big')+b'\x00'*8
            self.titlekey=aeskeydb.getCipher(0x3D, iv, CBC=True).decrypt(self.titlekey)
    def decrypt(self):
        header=struct.pack(">I",0x10004)
        header+=bytes(0x13C)
        header+=self.issuer
        header+=self.pubkey
        header+=struct.pack("<BBB",self.version,self.caCrlVersion,self.signerCrlVersion)
        header+=self.enckey
        header+=b'\x00'
        header+=struct.pack("<LILxxHxxxxxxxBBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxIxB",self.tickid,self.cid,self.tid,self.tikTitleVersion,self.licenseType,self.keyYindex,self.eshopAID,self.audit)
        header+=bytes(0x42)
        header+=self.limits
        header+=self.contentIndex
        return header
