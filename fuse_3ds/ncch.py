
import struct
from . import crypto
import hashlib
class NCCH:
    def __init__(self, f,ip):
        self.ip=ip
        self.f=f
        header=self.f.read(512)
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
        self.nocrypto=self.flags[7]&0x4
        self.keyY=header[:16]
        self.doExHeader()
    def addCtr(self,ctr,val):
        c=int.from_bytes(ctr,byteorder="big")
        c+=val
        return c.to_bytes(16,byteorder="big")
    def getCtr(self):
        ctr=bytearray(16)
        if self.version == 1:
            for c,b in enumerate(self.partID.to_bytes(8,byteorder="little")):
                ctr[c]=b

        else:
            for c,b in enumerate(self.partID.to_bytes(8,byteorder="big")):
                ctr[c]=b
        return bytes(ctr)


    def read(self,sectorno,sectors=1):
        f=self.f
        f.seek(sectorno*512)
        decdata=b''
        if self.nocrypto:
            return f.read(sectors*512)
        if sectorno == 0:
            #Sector is unencrypted
            data=f.read(512)

            decdata+=data[:0x18F]+bytes([data[0x18F]|0x04])+data[0x190:]
            if sectors == 1:
                return decdata
            sectorno+=1
            sectors-=1
        if sectorno >= 1 and sectorno < 5:
            ctr=self.getCtr()
            if self.version == 1:
                ctr=self.addCtr(ctr,sectorno*32+512-32)
            else:
                ctr = ctr[:8] + b'\x01' + ctr[9:]
                ctr=self.addCtr(ctr,sectorno*32-32)

            #Sector is encrypted using keyslot 0x2C
            csectors=min(sectors,4)
            sectors-=csectors
            data = f.read(csectors*512)
            if self.flags[7]&0x04: #Except when it's decrypted
                decdata += data
            else:
                decdata += crypto.cryptoBytestring(self.ip,data,0x6C,3,ctr,self.keyY)
            if not sectors:
                return decdata
            sectorno+=csectors
        ctr=self.getCtr()
        print(sectorno)
        if sectorno < self.exefsOff + self.exefsSize:
            print("EXE")
            #exefs
            if self.version == 1:
                ctr = self.addCtr(ctr,(sectorno-self.exefsOff)*32+self.exefsOff*512)
            else:
                ctr = ctr[:8] + b'\x02' + ctr[9:]
                ctr=self.addCtr(ctr,(sectorno-self.exefsOff)*32)
            overhang=sectors-self.exefsSize
            if overhang>0:
                return decdata + self.read(sectorno,self.exefsSize) + self.read(self.exefsOff+self.exefsSize,overhang)
        else:
            print("ROM")
            #romfs
            if self.version == 1:
                ctr = self.addCtr(ctr,(sectorno-self.romfsOff)*32+self.romfsOff*512)
            else:
                ctr = ctr[:8] + b'\x03' + ctr[9:]
                ctr=self.addCtr(ctr,(sectorno-self.romfsOff)*32)

        print(ctr)
        #Sectors are encrypted via multiple methods
        data=f.read(sectors*512)
        keyslot = 0x6C
        if self.flags[3] == 0x01:
            keyslot = 0x65
        elif self.flags[3] == 0x0A:
            keyslot = 0x58
        elif self.flags[3] == 0x0B:
            keyslot = 0x5B
        print(keyslot)
        decdata += crypto.cryptoBytestring(self.ip,data,keyslot,3,ctr,self.keyY)
        return decdata

    def doExHeader(self):
        self.exheader=self.read(1,(2048//512))
        if not self.exheadersize:
            return
        #Hash checking...
        if self.exheaderhash != hashlib.sha256(self.exheader[:self.exheadersize]).digest():
            print("WARNING: ExHeader hash mismatch!")
            print(self.exheaderhash,hashlib.sha256(self.exheader[:self.exheadersize]).digest())
