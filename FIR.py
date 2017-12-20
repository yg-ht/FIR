#!/usr/bin/env python3

#app modules below
import settings
import definitions
import functions

#python modules below
import sys
import os
import argparse


parser = argparse.ArgumentParser(description='FIR - Fast Initial Recon, a tool to extract details about a given network in a way that is efficient for penetration testing', version=settings.__version__)
parser.add_argument("-N", "--targetNetwork", action="store", default="127.0.0.1/32", help="Specify the target network in CIDR notaton.", dest="targetNetwork")
args = parser.parse_args()

if not os.geteuid() == 0:
    print("[!] Must be run as root.")
    sys.exit(-1)

def main():
    functions.buildmainarrays(args.targetNetwork)
    functions.portScan(args.targetNetwork, 8000, settings.nmapGenericSettings)


if __name__ == '__main__':
    main()