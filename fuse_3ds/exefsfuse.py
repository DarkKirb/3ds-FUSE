#!/usr/bin/env python3
import logging
from errno import ENOENT, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from time import time
import subprocess
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
import struct

class ExeFS(LoggingMixIn, Operations):
    def __init__(self,fname,mount):
        self.f=open(fname,"rb")
        self.files={}
        self.header=self.f.read(0x200)
        self.filelocs={}
        self.fd=1
        now=time()
        self.files["/"]=dict(st_mode=(S_IFDIR |0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2)
        for i in range(10):
            fname,off,size=struct.unpack("<8sII",self.header[i*0x10:(i+1)*0x10])
            if not size:
                continue
            x=""
            for c in fname[:]:
                if c :
                    x+=chr(c)
            fname=x
            self.files["/"+fname]=dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=size, st_blocks=(size+511)//512)
            self.filelocs["/"+fname]=off+512
    def chmod(self, path, mode):
        raise FuseOSError(EIO)
    def chown(self, path, uid, gid):
        raise FuseOSError(EIO)
    def create(self, path, mode):
        raise FuseOSError(EIO)
    def getattr(self,path,fh=None):
        if path not in self.files:
            raise FuseOSError(ENOENT)
        return self.files[path]
    def getxattr(self,path,name,position=0):
        return ''
    def listxattr(self,path):
        return []
    def mkdir(self,path,mode):
        raise FuseOSError(EIO)
    def open(self,path,flags):
        self.fd+=1
        return self.fd
    def read(self,path,size,offset,fh):
        self.f.seek(self.filelocs[path]+offset)
        return self.f.read(size)
    def readdir(self, path, fh):
        return ['.','..'] + [x[1:] for x in self.files if x != '/']
    def readlink(self, path):
        return self.data[path]
    def removexattr(self, path, name):
        raise FuseOSError(EIO)
    def rename(self, old, new):
        raise FuseOSError(EIO)
    def rmdir(self, path):
        raise FuseOSError(EIO)
    def setxattr(self, path, name, value, options, position=0):
        raise FuseOSError(EIO)
    def statfs(self,path):
        return dict(f_bsize=512, f_blocks=4096, f_bavail=0)
    def symlink(self, target, source):
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
    print("usage: {name} <EXEFS> <mountpoint>".format(name=argv[0]))
    exit(1)
logging.basicConfig(level=logging.WARNING)
fuse = FUSE(ExeFS(argv[1], argv[2]),argv[2], foreground=False)
