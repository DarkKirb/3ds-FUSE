#!/usr/bin/env python3
import logging
from errno import ENOENT, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from time import time
import subprocess
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
import struct
class romfsFile:
    def __repr__(self):
        if self.isdir:
            s = "Directory '{}' with subdirs [".format(self.name)
            for subdir in self.children:
                s+=subdir.name+", "
            s+="] and files ["
            for fil in self.files:
                s+=fil.name+", "
            s+="]."
            return s
        return "File '{}' of size {} at {}".format(self.name,hex(self.length),hex(self.off))
class RomFS(LoggingMixIn, Operations):
    def traverse(self):
        parent,sibling,child,ffile,namelen=struct.unpack("<IIIIxxxxI",self.f.read(0x18))
        fi = romfsFile()
        fi.isdir=True
        fi.name=self.f.read(namelen)
        fi.name=fi.name.decode("UTF-16")
        if len(fi.name) != 0:
            if fi.name[-1] == '\x00':
                fi.name=fi.name[:-1]
        fi.siblings=[]
        if sibling != 0xFFFFFFFF:
            self.f.seek(self.dirmetaOff+sibling)
            siblin = self.traverse()
            fi.siblings=[siblin]+siblin.siblings
        fi.children=[]
        if child != 0xFFFFFFFF:
            self.f.seek(self.dirmetaOff+child)
            chld = self.traverse()
            fi.children=[chld]+chld.siblings
        fi.files=[]
        if ffile != 0xFFFFFFFF:
            self.f.seek(self.filemetaOff+ffile)
            fil = self.traverse_file()
            fi.files=[fil]+fil.siblings
        return fi
    def traverse_file(self):
        parent,sibling,dataoff,datalen,namelen=struct.unpack("<IIQQxxxxI",self.f.read(0x20))
        fi = romfsFile()
        fi.isdir=False
        fi.name=self.f.read(namelen).decode("UTF-16")
        if len(fi.name) != 0:
            if fi.name[-1] == '\x00':
                fi.name=fi.name[:-1]
        fi.siblings=[]
        if sibling != 0xFFFFFFFF:
            self.f.seek(self.filemetaOff+sibling)
            siblin = self.traverse_file()
            fi.siblings=[siblin]+siblin.siblings
        fi.off=dataoff
        fi.length=datalen
        return fi
    def gentree(self,fi,path=""):
        name=path+fi.name
        root=False
        if name=="":
            root=True
            name="/"
        if fi.isdir:
            name+="/"
            self.files[name[:-1]]=dict(st_mode=(S_IFDIR | 0o555), st_ctime=self.now, st_mtime=self.now, st_atime=self.now, st_nlink=2)
            if root:
                name=name[:-1]
            for subdir in fi.children:
                self.gentree(subdir, name)
            for fil in fi.files:
                self.gentree(fil, name)
            return
        self.filelocs[name] = fi.off
        self.files[name]=dict(st_mode=(S_IFREG | 0o555), st_ctime=self.now, st_mtime=self.now, st_atime=self.now, st_nlink=2, st_size=fi.length, st_blocks=(fi.length+511)//512)
    def __init__(self,fname,mount):
        def align(a,b):
            if a%b:
                return a-(a%b)+b
            return a
        self.f=open(fname,"rb")
        print("Reading header")
        self.header=self.f.read(0x5C)
        masterhashsize=struct.unpack("<I",self.header[0x08:0x0C])[0]
        hashblocksize=1<<struct.unpack("<I",self.header[0x4C:0x50])[0]
        v=align(0x5C+masterhashsize,hashblocksize)
        self.f.seek(v)
        print("Reading l3 header")
        self.level3h=self.f.read(0x28)
        self.dirmetaOff,self.dirmetaSize,self.filemetaOff,self.filemetaSize,self.fileDataOff=struct.unpack("<IIxxxxxxxxIII",self.level3h[0xC:0x28])
        self.dirmetaOff+=v
        self.filemetaOff+=v
        self.fileDataOff+=v
        self.f.seek(self.dirmetaOff)
        self.root=self.traverse()
        self.filelocs={}
        self.fd=1
        self.now=time()
        self.files={}
        self.gentree(self.root)
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
        self.f.seek(self.filelocs[path]+offset+self.fileDataOff)
        return self.f.read(size)
    def readdir(self, path, fh):
        print(path)
        files=['.','..']
        for fi in self.files.keys():
            sp=fi.split("/")
            if len(sp) != 2 or path != "/":
                if '/'.join(sp[:-1]) != path:
                    continue
            if fi=="/":
                continue
            files.append(sp[-1])
        return files
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
    print("usage: {name} <ROMFS> <mountpoint>".format(name=argv[0]))
    exit(1)
logging.basicConfig(level=logging.WARNING)
fuse = FUSE(RomFS(argv[1], argv[2]),argv[2], foreground=False)
