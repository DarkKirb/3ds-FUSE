import cia
import struct
import crypto
class NCCH:
    def __init__(self, fname):
        self.f=open(fname,"rb")
        self.cia=cia.CIA(self.f)
        header=self.cia.read(0)
        self.header=header
        if b'NCCH' != header[0x100:0x104]:
            raise ValueError("This is not a valid NCCH file!")
        self.contentSize,self.partID,self.makerCode,self.version,self.programID=struct.unpack("<IQHHxxxxQ",header[0x104:0x120])
        self.productCode=header[0x150:0x160]
        print("Product code:",self.productCode.decode("UTF-8"))
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
        ctr=self.getCtr(1)
        data=self.cia.read(1,(self.exheadersize//512)+1)
        self.exheader=crypto.cryptoBytestring("192.168.2.105",data,0x6C,3,ctr,self.header[:0x10])

    def read(self,sectorno,sectors=1):
        pass
