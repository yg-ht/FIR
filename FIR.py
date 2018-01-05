#!/usr/bin/env python

#app modules below
import settings

#python modules below
import sys
import os
import argparse
#import asyncio

parser = argparse.ArgumentParser(description='FIR - Fast Initial Recon, a tool to extract details about a given network in a way that is efficient for penetration testing')
parser.add_argument("-N", "--targetNetwork", action="store", default="127.0.0.1/32", help="Specify the target network in CIDR notaton.", dest="targetNetwork")
parser.add_argument("-V", '--version', action='version', version=settings.__version__)
args = parser.parse_args()

if not os.geteuid() == 0:
    print("[!] Must be run as root.")
    sys.exit(-1)

def quit(self):
    self.sys.exit(0)

def main():
    from functions import FastInitialRecon
    FIR = FastInitialRecon(args.targetNetwork)

if __name__ == '__main__':
    main()