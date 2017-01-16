import struct
import hashlib
class TMD:
    def __init__(self, f):
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
        self.bootContent=struct.unpack(">I",f.read(4))[0]
        sha=f.read(0x20) #SHA256 of content info record
        contentInfoRecord=f.read(64*0x24)
        contentChunkRecord=[f.read(0x30) for x in range(self.contentCount)]
        checksha=hashlib.sha256(contentInfoRecord).digest()
        if sha != checksha:
            print("WARNING: TMD content info record hash mismatch!")
        for c in range(64):
            record=contentInfoRecord[:0x24]
            contentInfoRecord=contentInfoRecord[0x24:]
            content={}
            content["indexOffset"],content["commandCount"]=struct.unpack(">HH",record[:4])
            sha=record[4:]
            if c >= self.contentCount:
                continue
            checkstr=b""
            for s in contentChunkRecord[c:c+content["commandCount"]]:
                checkstr+=s
            checksha=hashlib.sha256(checkstr).digest()
            if content["commandCount"] and checksha != sha:
                print("WARNING: TMD content chunk record hash mismatch!")
            self.contents.append(content)
        self.contentHashes=[]
        for no,c in enumerate(contentChunkRecord):
            self.contents[no]["cid"],self.contents[no]["index"],self.contents[no]["type"],self.contents[no]["size"]=struct.unpack(">IHHQ",c[:0x10])
            self.contentHashes.append(c[0x10:])
