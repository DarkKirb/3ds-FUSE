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
        self.contentInfoRecord=list(contentInfoRecord)
        contentChunkRecord=[f.read(0x30) for x in range(self.contentCount)]
        self.contentChunkRecord=list(contentChunkRecord)
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
    def decrypt(self):
        contents=list(self.contents)
        contentChunkRecord=[]
        #modify content chunk records and rebuild them
        for no,c in enumerate(contents[:]):
            contents[no]=dict(c)
        for no,c in enumerate(contents):

            if c["type"] & 1:
                c["type"]&=~1 #unset encryption bit
            record=struct.pack(">IHHQ",c["cid"],c["index"],c["type"],c["size"])
            record+=self.contentHashes[no]
            contentChunkRecord.append(record)
        contentInfoRecord=b''
        #fix content info record hashes and rebuild them
        for no in range(64):
            sha=bytes(32)
            try:
                h=struct.pack(">HH",contents[no]["indexOffset"],contents[no]["commandCount"])
                #Recalculate sha
                if contents[no]["commandCount"]:
                    checkstr=b""
                    for s in contentChunkRecord[no:no+contents[no]["commandCount"]]:
                        checkstr+=s
                    sha=hashlib.sha256(checkstr).digest()
            except:
                h=struct.pack(">HH",0,0)
            contentInfoRecord+=h+sha

        header=struct.pack(">I",0x010004)
        header+=bytes(0x13C)
        header+=self.issuer
        header+=struct.pack(">BBBxQQIHIIxxxxB",self.version,self.caCrlVersion,self.signerCrlVersion,self.sysVersion,self.tid,self.type,self.gid,self.savesize,self.privatesavesize,self.SRLFlag)
        header+=bytes(0x31)
        header+=struct.pack(">IHHI",self.accessRights,self.tversion,self.contentCount,self.bootContent)
        header+=hashlib.sha256(contentInfoRecord).digest() #Fix this hash
        header+=contentInfoRecord
        for c in contentChunkRecord:
            header+=c
        return header
