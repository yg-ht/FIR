class FastInitialRecon:
    #python3 modules
    import settings
    import os
    import nmap
    import sqlite3
    from sqlite3 import Error

    #custom modules
    import definitions

    def __init__(self, targetNetwork):
        from netaddr import IPNetwork

        try:
            self.os.remove(self.settings.dbFile)
        except OSError:
            pass

        self.databaseTransaction("CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        self.databaseTransaction("CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        self.databaseTransaction("CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        for hostAddr in IPNetwork(targetNetwork):
            self.databaseTransaction("INSERT INTO hosts (host) VALUES(?)", (str(hostAddr),))

    def databaseTransaction(self, query, params=False):
        try:
            db = self.sqlite3.connect(self.settings.dbFile)
            cursor = db.cursor()
            if params != False:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            db.commit()
            result = cursor.fetchall()
            db.close()
            return result
        except self.sqlite3.Error as e:
            print(e)

    def portScan(self, targetNetwork, targetPort, nmapGenericSettings):
        nm = self.nmap.PortScanner()
        nm.scan(targetNetwork, targetPort, nmapGenericSettings)
        for IP in nm.all_hosts():
            print("Port "+targetPort+" found open on host " + IP)
            hostID = self.databaseTransaction(self.dbFile, "SELECT id FROM hosts WHERE host=?", IP)
            self.databaseTransaction(self.dbFile, "INSERT INTO openPorts (hostID, portNum) VALUES(?, ?)", (hostID, targetPort))

    def storeFinding(self, IP, port, finding):
        print('blah')
