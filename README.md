# FIR
## Fast Initial Recon

This is a new project designed to automate early enumeration tasks.  Inspired by, amongst other things, Sparta
 (https://github.com/SECFORCE/sparta).  It is designed for time-constrained penetration tests, needless to say, this
 isn't exactly subtle - so I wouldn't use it if you are trying to stay under the radar.  It currently performs
 the following tasks:
 
 - A targeted TCP and UDP port scan
 - Checks to see if IPs are in rDNS and extracts hostnames and domain names where possible
 - An NBT Scan()
 - Checks which SMB Version is available and pulls certain details
 - Attempts to enumerate users via RPC / SMB
 - Looks for non-standard SMB file shares
 - Checks to see what access the anonymous user has to SMB file shares
 - Checks whether the target is vulnerable to MS08-067
 - Checks whether the target is vulnerable to MS17-010
 - Checks which SSH protocol version is in place
 - Check for SNMP services with default community strings
 - Checks is discovered hostnames are in any known DNS servers to attempt to confirm AD Domain membership
 - Checks is AXFR is enabled on any DNS servers for known domains
 - Looks for default credentials on MSSQL servers
 - Attempts to enumerate user accounts on the Finger service
 - Checks to see if SMTP will leak AD Domain info
 - Checks for SMTP enumeration of a given list of users

This is at beta stages in its development - please report bugs (or better still, submit pull requests)

## Installation / dependancies

This project is written for Python2.7, so make sure you have the below dependencies installed:

 - python-netaddr
 - python-psutil
 - python-nmap
 - python-texttable
 - python readchar

On ubuntu-based distributions (including Kali) you can use:

    apt update
    apt upgrade -y
    apt install python-netaddr python-nmap python-texttable python-psutil
    pip install readchar

You will also need to have Metasploit in good working order as this script takes advantage of the MSFRPCd.

This script should auto-detect MSFRPC running status and start if required, however, if you would rather do
this manually, update the settings.py file with your credentials and run MSFRPCd with something like:

    msfrpcd -U fir -P P455WORDh3r3 --ssl
    
## Future features (To do list)

To make this a minimum viable product for Fast Initial (noisey) Recon the following must be in place:

 - ftp anonymous login checking
 - ftp anonymous access rights
 - identify IIS / Apache versions (and associated exploitDB data)

## Thanks and acknowledgments

Thanks must go to the following people and code repositories as they have been invaluable in making this project:

 - many many friends, who I'm sure want to remain nameless
 - https://github.com/allfro/pymetasploit
