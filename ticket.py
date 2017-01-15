import struct
import crypto
import aeskeydb
class Ticket:
    def __init__(self, f):
        sigtype=struct.unpack(">I",f.read(4))[0]-0x10000
        skip=[0x23C,0x13C,0x7C,0x23C,0x13C,0x7C]
        f.read(skip[sigtype])
        self.issuer=f.read(0x40)
        self.pubkey=f.read(0x3C)
        self.version,self.caCrlVersion,self.signerCrlVersion=struct.unpack("<BBB",f.read(3))
        self.titlekey=f.read(0x10)
        f.read(1)
        self.tickid,self.cid,self.tid,self.tikTitleVersion,self.licenseType,self.keyYindex,self.eshopAID,self.audit=struct.unpack("<LILxxHxxxxxxxBBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxIxB",f.read(73))
        f.read(0x42)
        self.limits=f.read(0x40)
        f.read(0xAC)
        self.encrypted=self.titlekey != b'\xFF'*16
    def decryptTitleKey(self,tid):
        if self.encrypted:
            #Decrypt title key
            keyY=aeskeydb.getKey(0x3D)[2]
            iv=tid.to_bytes(8, byteorder='big')+b'\x00'*8
            self.titlekey=crypto.cryptoBytestring("192.168.2.105",self.titlekey,0x7D,1,iv,keyY)
