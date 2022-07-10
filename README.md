# FIR
## Fast Initial Recon

This tool is ropey as sin.  I suggest you don't use it and find a better way.  The latest set of fixes were put in place as a stop gap to make it work for a particular purpose.  YMMV

This is a new project designed to automate early enumeration tasks.  Inspired by, amongst other things, Sparta
 (https://github.com/SECFORCE/sparta).  It is designed for time-constrained penetration tests, needless to say, this
 isn't exactly subtle - so I wouldn't use it if you are trying to stay under the radar.  It currently performs
 the following tasks:
 
 - A targeted TCP and UDP port scan
 - Checks to see if IPs are in rDNS and extracts hostnames and domain names where possible
 - An NBT Scan
 - Checks which SMB Version is available and pulls certain details
 - Looks for non-standard SMB file shares
 - Checks to see what access the anonymous user has to SMB file shares
 - Checks whether the target is vulnerable to MS17-010
 - Checks which SSH protocol version is in place
 - Checks if AXFR is enabled on any DNS servers for known domains
 - Attempts to enumerate user accounts on the Finger service
 - Checks for SMTP enumeration of a given list of users

This is at beta stages in its development - please report bugs (or better still, submit pull requests)

## Installation / dependancies

This project is written for Python3, so make sure you have the below dependencies installed:

 - python3-netaddr
 - python3-psutil
 - python3-nmap
 - python3-texttable
 - python3 readchar

On ubuntu-based distributions (including Kali) you can use:

    sudo apt update
    sudo apt upgrade -y
    sudo apt install -y python3-netaddr python3-nmap python3-texttable python3-psutil
    sudo apt install -y smtp-user-enum
    sudo pip install readchar

You will also need to have Metasploit in good working order to take advantage of the hints provided if it discovers something interesting

## Future features (To do list)

To make this a minimum viable product for Fast Initial (noisey) Recon the following must be in place:

 - ftp anonymous login checking
 - ftp anonymous access rights
 - identify IIS / Apache versions (and associated exploitDB data)

## Thanks and acknowledgments

Thanks must go to the following people and code repositories as they have been invaluable in making this project:

 - many many friends, who I'm sure want to remain nameless
 - https://github.com/allfro/pymetasploit
