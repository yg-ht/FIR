#!/usr/bin/env python3

import sys
import optparse
import settings
import definitions
import functions

parser = optparse.OptionParser(usage='./%prog -N CIDR_mask', version=settings.__version__, prog=sys.argv[0])
parser.add_option('-N', '--network', action="store", help="Specify the target network.", dest="targetNetwork")
options, args = parser.parse_args()

functions.buildmainarrays(args.targetNetwork)
functions.portScan('127.0.0.1', 8000, settings.nmapGenericSettings)