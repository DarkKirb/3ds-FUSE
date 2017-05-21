#!/usr/bin/env python3
from fuse_3ds import cia

import logging
from errno import ENOENT, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from time import time
import subprocess
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

class CIA(LoggingMixIn, Operations):
    'Read only filesystem for CIA files.'
    def __init__(self,fname,mount):
        self.files={}
        self.f = open(fname,"rb")
        self.cia = cia.CIA(self.f)
        self.fd = 0
        now = time()
        self.files["/"] = dict(st_mode=(S_IFDIR | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2)
        self.files["/dec.cia"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.cia.size, st_blocks=(self.cia.size+511)//512)
        self.files["/ticket"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.cia.tikSize, st_blocks=(self.cia.tikSize+511)//512)
        self.files["/tmd"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.cia.tmdSize, st_blocks=(self.cia.tmdSize+511)//512)
        for no in range(self.cia.tmd.contentCount):
            ending=".cfa"
            if no == 0:
                ending=".cxi"
            self.files["/"+str(no)+ending]=dict(st_mode=(S_IFREG | 0o555),st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.cia.tmd.contents[no]["size"], st_blocks=(self.cia.tmd.contents[no]["size"]+511)//512)


    def chmod(self,path,mode):
        raise FuseOSError(EIO) #IT'S RO

    def chown(self, path, uid, gid):
        raise FuseOSError(EIO)

    def create(self,path,mode):
        raise FuseOSError(EIO)

    def getattr(self,path,fh=None):
        if path not in self.files:
            raise FuseOSError(ENOENT)

        return self.files[path]

    def getxattr(self,path,name,position=0):
        return ''

    def listxattr(self, path):
        return []

    def mkdir(self,path,mode):
        raise FuseOSError(EIO)

    def open(self,path,flags):
        self.fd += 1
        return self.fd
    def readDecCIA(self,path,size,offset):
        #Ok, read the decrypted CIA
        #If offset is before the actual contents, read that instead
        data=b''
        s=False
        if offset < self.cia.contentOff:
            s=True
            data=self.cia.getDecHeader()
            data=data[offset:offset+size]
            if len(data) == size:
                return data
        offset-=self.cia.contentOff
        if offset < 0:
            offset = 0
        #If not, or if not enough data is read, start in the correct sector, and read more than asked
        data+=self.cia.read(offset//512,((size-len(data))//512)+2)
        #Remove data at the beginning
        if s:
            data=data[offset%512:]
        #remove trailing data
        data=data[:size]
        return data
    def readContent(self,path,size,offset,content):
        start=self.cia.startSec(content)
        data=self.cia.read((offset//512)+start,(size//512)+2)
        data=data[offset%512:]
        data=data[:size]
        return data
    def read(self,path,size,offset,fh):
        if path == "/dec.cia":
            return self.readDecCIA(path,size,offset)
        if path == "/ticket":
            data=self.cia.ticket.decrypt()
            return data[offset:offset+size]
        if path == "/tmd":
            data=self.cia.tmd.decrypt()
            return data[offset:offset+size]
        for no in range(self.cia.tmd.contentCount):
            ending=".cfa"
            if no == 0:
                ending=".cxi"
            if path == "/"+str(no)+ending:
                #Found it!
                return self.readContent(path,size,offset,no)

        raise FuseOSError(EIO)


    def readdir(self, path, fh):
        return ['.', '..'] + [x[1:] for x in self.files if x != '/']

    def readlink(self, path):
        return self.data[path]

    def removexattr(self, path, name):
        raise FuseOSError(EIO)

    def rename(self, old, new):
        raise FuseOSError(EIO)

    def rmdir(self, path):
        raise FuseOSError(EIO)

    def setxattr(self,path,name,value,options,position=0):
        raise FuseOSError(EIO)

    def statfs(self,path):
        return dict(f_bsize=512, f_blocks=4096, f_bavail=0)

    def symlink(self,target,source):
        raise FuseOSError(EIO)

    def truncate(self,path,length,fh=None):
        raise FuseOSError(EIO)

    def unlink(self,path):
        raise FuseOSError(EIO)

    def utimens(self,path,times=None):
        raise FuseOSError(EIO)

    def write(self,path,data,offset,fh):
        raise FuseOSError(EIO)

    def flush(self,path,fh):
        pass
    def release(self,path,fh):
        pass

if len(argv) != 3:
    print('usage: {name} <CIA> <mountpoint>'.format(name=argv[0]))
    exit(1)
logging.basicConfig(level=logging.WARNING)
fuse = FUSE(CIA(argv[1], argv[2]),argv[2],foreground=False)
