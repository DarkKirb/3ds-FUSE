#Code copied/ported from 3ds-crypto-client
import sys
import struct
import socket
import binascii
import os

def send_all(sock, data):
    r = len(data)
    while len(data) > 0:
        data = data[sock.send(data):]

def recv_all(sock, size):
    data = b''
    while len(data) < size:
        data += sock.recv(size - len(data))
    return data
def cryptoBytestring(ip, data, keyslot,algo, iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',keyY=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
    keyslot+=0x80
    meta = struct.pack('<IIII',0xCAFEBABE, len(data), keyslot, algo)+keyY+iv+(b'\x00'*0x3D0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip,8081))
    sock.send(meta)
    bufsize = struct.unpack('<I',sock.recv(4))[0]
    ofs=0
    outdata=b''
    while ofs<len(data):
        if ofs + bufsize < len(data):
            send_all(sock, data[ofs:ofs+bufsize])
            outdata += recv_all(sock,bufsize)
        else:
            send_all(sock, data[ofs:])
            outdata += recv_all(sock, len(data)-ofs)
        ofs += bufsize

    send_all(sock,struct.pack('<I',0xDEADCAFE))
    blocked = False
    return outdata
def cryptofile(ip, infile, outfile, keyslot,algo, iv=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',keyY=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
    keyslot+=0x80
    size = os.path.getsize(infile.name)-infile.tell()
    meta = struct.pack('<IIII',0xCAFEBABE, size, keyslot, algo)+keyY+iv+(b'\x00'*0x3D0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip,8081))
    bufsize = struct.unpack('<I',sock.recv(4))[0]
    ofs=0
    while ofs<size:
        if ofs+bufsize < size:
            send_all(sock, infile.read(bufsize))
            outfile.write(recv_all(sock,bufsize))
        else:
            send_all(sock, infile.read())
            outfile.write(recv_all(sock, size-ofs))
        ofs += bufsize
    send_all(sock, struct.pack('<I',0xDEADCAFE))
