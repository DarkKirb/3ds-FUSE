#!/usr/bin/env python3
from fuse_3ds import ncch

import logging
from errno import ENOENT, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from time import time
import subprocess
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

class NCCH(LoggingMixIn, Operations):
    'Read only filesystem for NCCH files.'
    def __init__(self,fname,mount):
        self.files={}
        self.f = open(fname,"rb")
        self.ncch = ncch.NCCH(self.f)
        self.type="cxi" if self.ncch.exefsSize else "cfa"
        self.fd = 0
        now = time()
        self.files["/"] = dict(st_mode=(S_IFDIR | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2)
        self.files["/dec."+self.type] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=512*(self.ncch.romfsOff+self.ncch.romfsSize), st_blocks=self.ncch.romfsOff+self.ncch.romfsSize)
        if self.type == "cxi":
            self.files["/exefs.bin"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.ncch.exefsSize*512, st_blocks=self.ncch.exefsSize)
        if self.ncch.exheadersize:
            self.files["/exheader.bin"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.ncch.exheadersize, st_blocks=(self.ncch.exheadersize+511)//512)
        if self.ncch.plainregionSize:
            self.files["/plainrgn.bin"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.ncch.plainregionSize*512, st_blocks=self.ncch.plainregionSize)
        if self.ncch.logoregionSize:
            self.files["/logorgn.bin"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.ncch.logoregionSize*512, st_blocks=self.ncch.logoregionSize)
        if self.ncch.romfsSize:
            self.files["/romfs.bin"] = dict(st_mode=(S_IFREG | 0o555), st_ctime=now, st_mtime=now, st_atime=now, st_nlink=2, st_size=self.ncch.romfsSize*512, st_blocks=self.ncch.romfsSize)


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
    def readDecNCCH(self,path,size,offset):
        header=self.ncch.header
        header=header[:0x188+7]+b'\x04'+header[0x189+7:]
        if offset == 0:
            endSize = size-512
            if endSize <= 0:
                return header[:size]
            return header+self.readDecNCCH(path, offset+512,endSize)
        data=self.ncch.read((offset//512),(size//512)+2)
        return data[:size]
    def read(self,path,size,offset,fh):
        if path[:5] == "/dec.":
            return self.readDecNCCH(path,size,offset)
        if path == "/exefs.bin":
            return self.readDecNCCH(path,size,offset+self.ncch.exefsOff*512)
        if path == "/exheader.bin":
            return self.readDecNCCH(path,size,offset+512)
        if path == "/plainrgn.bin":
            return self.readDecNCCH(path,size,offset+self.ncch.plainregionOff*512)
        if path == "/logorgn.bin":
            return self.readDecNCCH(path,size,offset+self.ncch.logoregionOff*512)
        if path == "/romfs.bin":
            return self.readDecNCCH(path,size,offset+self.ncch.romfsOff*512)

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
    print('usage: {name} <NCCH> <mountpoint>'.format(name=argv[0]))
    exit(1)
logging.basicConfig(level=logging.DEBUG)
fuse = FUSE(NCCH(argv[1], argv[2]),argv[2],foreground=True)
