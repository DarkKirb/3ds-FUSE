#!/usr/bin/env python3
from setuptools import setup
setup(name="3ds-fuse",
      version="0.1.1",
      description="FUSE filesystems for different 3DS file types",
      author="Morten Delenk",
      author_email="morten@dark32.cf",
      packages=["fuse_3ds"],
      scripts=["fuse_3ds/ciafuse.py","fuse_3ds/exefsfuse.py","fuse_3ds/ncchfuse.py","fuse_3ds/romfsfuse.py","fuse_3ds/3dsxfuse.py"],
      install_requires=["fusepy","pycryptodome"])

