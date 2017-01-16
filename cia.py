import struct
import crypto
import ticket
import tmd
import ncch
import hashlib
import sys
from Crypto.Cipher import AES
def align(x,y):
    mask = ~(y-1)
    return (x+(y-1))&mask
class CIA:
    def __init__(self, f):
        self.f=f
        self.headerSize,self.type,self.version,self.cachainSize,self.tikSize,self.tmdSize,self.metaSize,self.contentSize=struct.unpack("<IHHIIIIQ",self.f.read(0x20))
        self.cachainOff=align(self.headerSize,64)
        self.tikOff=align(self.cachainOff+self.cachainSize,64)
        self.tmdOff=align(self.tikOff+self.tikSize,64)
        self.contentOff=align(self.tmdOff+self.tmdSize,64)
        self.metaOff=align(self.contentOff+self.contentSize,64)
        for e,f,g in [("Header:",0,self.headerSize),("CA chain",self.cachainOff,self.cachainSize),("Ticket:",self.tikOff,self.tikSize),("TMD:",self.tmdOff,self.tmdSize),("Content:",self.contentOff,self.contentSize),("Metadata:",self.metaOff,self.metaSize)]:
            print(e,hex(f),hex(g))
        self.f.seek(self.cachainOff)
        self.cachain=self.f.read(self.cachainSize)
        self.f.seek(self.tikOff)
        self.ticket=ticket.Ticket(self.f)
        self.f.seek(self.tmdOff)
        self.tmd=tmd.TMD(self.f)
        self.ticket.decryptTitleKey(self.tmd.tid)
        self.f.seek(self.contentOff)
        self.ncchs=[]
        off=0
        for nc in range(len(self.tmd.contents)):
            self.ncchs.append(ncch.NCCH(f,self,off//512))
            off+=self.tmd.contents[nc]["size"]
    def hashCheck(self):
        print("Doing hash checks. This may take a while")
        self.f.seek(self.contentOff)
        secno=0
        for no,content in enumerate(self.tmd.contents):
            sha=hashlib.sha256()
            for cno in range(content["size"]//512):
                sha.update(self.read(secno))
                if not cno % 2048:
                    print(".",end="")
                    sys.stdout.flush()
                secno+=1
            print()
            sha=sha.digest()
            if sha != self.tmd.contentHashes[no]:
                print("WARNING: Section",no,"hash mismatch!")

    def getContentNo(self,sector):
        byte=sector*512
        for f in self.tmd.contents:
            if byte < f["size"]:
                return f["index"]
            byte-=f["size"]
    def contentSector(self,sector):
        byte=sector*512
        for f in self.tmd.contents:
            if byte < f["size"]:
                return byte//512
            byte-=f["size"]
    def read(self,sectorno,sectors=1):
        """
        NOTE: Only reads whole sectors!
        """
        self.f.seek(self.contentOff+sectorno*512)
        if not self.tmd.contents[self.getContentNo(sectorno)]["type"]&1:
            #Just read the unencrypted data
            return self.f.read(sectors*512)
        iv=b''
        if not self.contentSector(sectorno):
            iv=self.tmd.contents[self.getContentNo(sectorno)]["index"].to_bytes(2,byteorder="big")+b'\x00'*14
        else:
            self.f.seek((self.contentOff+sectorno*512)-16)
            iv=self.f.read(16)
        cipher=AES.new(self.ticket.titlekey, AES.MODE_CBC, iv)
        return cipher.decrypt(self.f.read(sectors*512))
