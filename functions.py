class FastInitialRecon:
    def __init__(self, targetNetwork):
        from netaddr import IPNetwork
        import os

        import settings
        import definitions

        try:
            os.remove(settings.dbFile)
        except OSError:
            pass

        self.databaseTransaction(settings.dbFile, "CREATE TABLE hosts (id INTEGER PRIMARY KEY, host TEXT)")
        self.databaseTransaction(settings.dbFile, "CREATE TABLE openPorts (id INTEGER PRIMARY KEY, hostID INTEGER, portNum INTEGER, FOREIGN KEY (hostID) REFERENCES hosts(id))")
        self.databaseTransaction(settings.dbFile, "CREATE TABLE findings (id INTEGER PRIMARY KEY, openPortID INTEGER, finding TEXT, FOREIGN KEY (openPortID) REFERENCES openPorts(id))")
        for hostAddr in IPNetwork(targetNetwork):
            self.databaseTransaction(settings.dbFile, "INSERT INTO hosts (host) VALUES(?)", (str(hostAddr),))

    def databaseTransaction(self, dbFile, query, params=False):
        import sqlite3
        from sqlite3 import Error
        try:
            db = sqlite3.connect(dbFile)
            cursor = db.cursor()
            if params != False:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            db.commit()
            db.close()
        except Error as e:
            print(e)

    def portScan(targetNetwork, targetPort, nmapGenericSettings):
        import nmap
        nm = nmap.PortScanner()
        nm.scan(targetNetwork, targetPort, nmapGenericSettings)
        for IP in nm.all_hosts():
            print(IP)
            [IP][targetPort].append('Open')

    def storeFinding(self, IP, port, finding):
        print('blah')
