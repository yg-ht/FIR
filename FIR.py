#!/usr/bin/env python3

import sys
import os
import optparse
import settings
import definitions
import functions

parser = optparse.OptionParser(usage='./%prog -N CIDR_mask', version=settings.__version__, prog=sys.argv[0])
parser.add_option('-N', '--network', action="store", help="Specify the target network.", dest="targetNetwork", default="127.0.0.1/32")
options, args = parser.parse_args()

if not os.geteuid() == 0:
    print("[!] Must be run as root.")
sys.exit(-1)

functions.buildmainarrays(args.targetNetwork)
functions.portScan(args.targetNetwork, 8000, settings.nmapGenericSettings)