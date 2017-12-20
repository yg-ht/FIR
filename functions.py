from netaddr import IPNetwork

def buildmainarrays(targetNetwork):
    hosts = []
    for ip in IPNetwork(targetNetwork):
        #[IP, general notes]
        hosts.append([ip, ""])

    findings = [
        #[port_host_ID, "finding text"]
        [1, "Test Finding"]
    ]

    port_host = [
        #[ports_ID, hosts_ID]
        [1, 1]
    ]

def portScan(targetNetwork, targetPort, nmapGenericSettings):
    import nmap
    nm = nmap.PortScanner()
    nm.scan(targetNetwork, targetPort, nmapGenericSettings)
    for host in nm.all_hosts():
        print(targetNetwork)
        print(nm[host].all_tcp())