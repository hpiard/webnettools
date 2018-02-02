import sslscan

def check_cert_details_heartbleed():
    sc = sslscan.Scanner()
    sc.set_handler('http')
    #sc.append('vuln.heartbleed')
    #sc.load_rating('ssllabs.2009c')
    x = sc.run('146.20.90.160')
    print x

check_cert_details_heartbleed()