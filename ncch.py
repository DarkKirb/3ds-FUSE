import cia
import struct
import crypto
import hashlib
class NCCHfile:
    def __init__(self, f):
        self.ncch=NCCH(f,self)
    def read(self,sectorno,sectors):
        f.seek(sectorno*512)
        return f.read(sectors*512)
class NCCH:
    def __init__(self, f,cia,offset=0):
        self.f=f
        self.cia=cia
        self.offset=offset
        header=self.cia.read(offset+0)
        self.header=header
        if b'NCCH' != header[0x100:0x104]:
            raise ValueError("This is not a valid NCCH file!")
        self.contentSize,self.partID,self.makerCode,self.version,self.programID=struct.unpack("<IQHHxxxxQ",header[0x104:0x120])
        self.productCode=header[0x150:0x160]
        print("Product code:",self.productCode.decode("UTF-8"))
        self.exheaderhash=header[0x160:0x180]
        self.exheadersize=struct.unpack("<I",header[0x180:0x184])[0]
        self.flags=struct.unpack("<BBBBBBBB",header[0x188:0x190])
        self.plainregionOff,self.plainregionSize,self.logoregionOff,self.logoregionSize,self.exefsOff,self.exefsSize,self.exefsHash,self.romfsOff,self.romfsSize,self.romfsHash=struct.unpack("<IIIIIIIxxxxIIIxxxx",header[0x190:0x1C0])
        self.crypto7x=self.flags[3]
        self.cryptoSeed=self.flags[7] & 0x20
        self.cryptoSec3=self.flags[3]==0x0A
        self.cryptoSec4=self.flags[3]==0x0B
        self.cryptoFixkey=self.flags[7]&1
        self.doExHeader()
    def addCtr(self,ctr,val):
        c=int.from_bytes(ctr,byteorder="big")
        c+=val
        return c.to_bytes(16,byteorder="big")
    def getCtr(self,id):
        ctr=bytearray(16)
        if self.version == 1:
            for c,b in enumerate(self.partID.to_bytes(8,byteorder="little")):
                ctr[c]=b
            if id == 1:
                ctr=self.addCtr(ctr,0x200)
            elif id == 2:
                ctr=self.addCtr(ctr,self.exefsOff*0x200)
            elif id == 3:
                ctr=self.addCtr(ctr,self.romfsOff*0x200)
        else:
            for c,b in enumerate(self.partID.to_bytes(8,byteorder="big")):
                ctr[c]=b
            ctr[8]=id
        return bytes(ctr)

    def doExHeader(self):
        data=self.cia.read(self.offset+1,(2048//512))
        if not self.exheadersize:
            return
        if self.flags[7]&0x04:
            self.exheader=data
        else:
            ctr=self.getCtr(1)
            self.exheader=crypto.cryptoBytestring("192.168.2.105",data,0x6C,3,ctr,self.header[:0x10])
        #Hash checking...
        if self.exheaderhash != hashlib.sha256(self.exheader[:self.exheadersize]).digest():
            print("WARNING: ExHeader hash mismatch!")
            print(self.exheaderhash,hashlib.sha256(data).digest())

    def read(self,sectorno,sectors=1):
        pass
