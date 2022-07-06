import time

__version__ = 'FIR 0.5 ALPHA'

debug = False
verbose = True

dbFile = 'FIR.sqlite'

nmapGenericSettingsTCP = '--open -n -Pn -sS -T4'
nmapGenericSettingsUDP = '--open -n -Pn -sU -sV  --version-intensity 0 -T5'

portsForScanning_TCP = [21, 22, 23, 25, 53, 79, 80, 137, 138, 139, 389, 443, 445, 512, 513, 514, 636, 990, 1433, 3389, 3306, 5800, 5900, 8000, 8080]
portsForScanning_UDP = [53, 161]

#portsForScanning_TCP = [139, 445] # test limiter
#portsForScanning_UDP = [] # test limiter

dnsTimeoutSeconds = 1
