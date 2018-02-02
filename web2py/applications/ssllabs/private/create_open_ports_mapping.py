# You need to run this as root!


import nmap
import sqlite3
import sys
from datetime import datetime, date, time


def populate_usips_database():
    dbconn = sqlite3.connect('../databases/storage.ssllabs.sqlite')
    c = dbconn.cursor()
    nm = nmap.PortScanner()
    with open(sys.argv[1], 'r') as iplist:
        for ip in iplist:
            scanip = ip.rstrip()
            try:
                nm.scan(scanip, '80,443,8443,8080')
                ports = nm[scanip].all_tcp()
                #print ports
                open_port_list = []
                for item in ports:
                    if nm[scanip]['tcp'][item]['state'] == 'open':
                        open_port_list.append(item)
                #print open_port_list
                open_ports = str(open_port_list)
                utctimenow = datetime.utcnow()
                print "Host: " + scanip + " Open tcp ports: " + open_ports
                c.execute('''INSERT INTO us_ips(ip_address, open_port, datetime)VALUES(?,?,?)''', (scanip, open_ports, \
                                                                                                   utctimenow))
                dbconn.commit()
            except KeyError as e:
                #print e
                #print scanip
                if e:
                    utctimenow = datetime.utcnow()
                    down_message = "Host down or not reachable!"
                    print "Host: " + scanip + " Open tcp ports: " + down_message
                    c.execute('''INSERT INTO us_ips(ip_address, open_port, datetime)VALUES(?,?,?)''',
                              (scanip, down_message, utctimenow))
                    dbconn.commit()
        dbconn.close()


populate_usips_database()
