#!/usr/bin/env python3
import logging
from errno import ENOENT, EIO
from stat import S_IFDIR, S_IFLNK, S_IFREG
from sys import argv, exit
from time import time
import subprocess
from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
from fuse_3ds.romfs import *
import struct
class RomFS(RomFSBase):
    def __init__(self,fname,mount):
        f=open(fname,"rb")
        header=f.read(0x20)
        if header[:4] != b"3DSX":
            raise ValueError("This is not a 3dsx file!")
        size=struct.unpack("<H",header[4:6])[0]
        if size == 0x20:
            raise ValueError("There is no romfs in this 3dsx.")
        smdhOff,smdhSize,romfsOff=struct.unpack("<III",f.read(0xC))
        f.seek(romfsOff)
        super(RomFS, self).__init__(f, mount, True)
if len(argv) != 3:
    print("usage: {name} <3dsx> <mountpoint>".format(name=argv[0]))
    exit(1)
logging.basicConfig(level=logging.WARNING)
fuse = FUSE(RomFS(argv[1], argv[2]),argv[2], foreground=False)
