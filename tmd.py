import struct
class TMD:
    def __init__(self, f):#
        sigtype=struct.unpack(">I",f.read(4))[0]-0x10000
        skip=[0x23C,0x13C,0x7C,0x23C,0x13C,0x7C]
        f.read(skip[sigtype])
        loc=f.tell()+0xC4
        #Reading the TMD header
        self.issuer=f.read(0x40)
        self.version,self.caCrlVersion,self.signerCrlVersion,self.sysVersion=struct.unpack(">BBBxQ",f.read(12))
        self.tid=struct.unpack(">Q",f.read(8))[0]
        self.type,self.gid,self.savesize,self.privatesavesize,self.SRLFlag=struct.unpack(">IHIIxxxxB",f.read(19))
        f.read(0x31)
        self.accessRights,self.tversion,self.contentCount=struct.unpack(">IHH",f.read(8))
        self.contents=[]
        for c in range(64):
            f.read(0x24)
            pass
        self.bootContent=struct.unpack(">Hxx",f.read(4))
        f.read(0x20) #skip sha256 hash
        f.seek(loc)
        for c in range(64):
            content={}
            content["indexOffset"],content["commandCount"]=struct.unpack(">HH",f.read(4))
            f.read(0x20)
            if c >= self.contentCount:
                continue
            self.contents.append(content)
        for c in range(min(self.contentCount,64)):
            self.contents[c]["cid"],self.contents[c]["index"],self.contents[c]["type"],self.contents[c]["size"]=struct.unpack(">IHHQ",f.read(16))
            f.read(0x20)
