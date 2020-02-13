#!/usr/bin/env python
#! -*- Encoding: utf-8 -*-
import sys, os
import argparse
sys.dont_write_bytecode = True
from MeTh.core.base import * 
from MeTh.core.colors import *

def Framework(argv):
 meth = MeTh()
 if len(argv[1:]):
  #meth.nonInteractive(argv)
  print("No interactive shell will be added :)")
 else:
  meth.start()
if __name__ == "__main__":
    try:
        Framework(sys.argv)
    except (KeyboardInterrupt, SystemExit):
        pass