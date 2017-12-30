#!/usr/bin/env python

#app modules below
import settings

#python modules below
import sys
import os
import argparse

parser = argparse.ArgumentParser(description='FIR - Fast Initial Recon, a tool to extract details about a given network in a way that is efficient for penetration testing')
parser.add_argument("-N", "--targetNetwork", action="store", default="127.0.0.1/32", help="Specify the target network in CIDR notaton.", dest="targetNetwork")
parser.add_argument("-V", '--version', action='version', version=settings.__version__)
args = parser.parse_args()

if not os.geteuid() == 0:
    print("[!] Must be run as root.")
    sys.exit(-1)

def main():
    from functions import FastInitialRecon
    FIR = FastInitialRecon(args.targetNetwork)
    for targetPort in settings.portsForScanning_TCP:
        print("Scanning to see if TCP/"+str(targetPort)+" is open on any in-scope IP")
        FIR.portScan_TCP(args.targetNetwork, str(targetPort), settings.nmapGenericSettings)
    FIR.printDiscoveredOpenPorts()

if __name__ == '__main__':
    main()