@auth.requires_login()
def certhealth():
    ip_addresses = db().select(db.us_ips.ALL, orderby=db.us_ips.ip_address)
    return dict(ip_adresses=ip_addresses)


@auth.requires_login()
def checkports():
    import ast
    import os
    import subprocess
    db_request = db.us_ips(request.args(0, cast=int, otherwise=URL('error'))) or redirect(URL('ssllabs', 'index'))
    ports = db_request['open_port']
    ports_as_list = ast.literal_eval(ports)
    #print ports_as_list
    if 443 in ports_as_list:
    #   pysslscan_cmd = os.system("pysslscan scan --scan=protocol.http --scan=vuln.heartbleed --scan=server.renegotiation" \
    #                     " --scan=server.preferred_ciphers --scan=server.ciphers   --report=term:rating=ssllabs.2009e"
    #                     " --ssl2 --ssl3 --tls10 --tls11 --tls12 http://" + db_request['ip_address'])
        pysslscan_cmd = "pysslscan scan --scan=protocol.http --scan=vuln.heartbleed --scan=server.renegotiation" \
                        " --scan=server.preferred_ciphers --scan=server.ciphers --report=term" \
                        " --ssl2 --ssl3 --tls10 --tls11 --tls12 http://" + db_request['ip_address'] + "> " + \
                        request.folder + "private/pysslscan_ascii_esc.tmp"
    #   print pysslscan_cmd
        result = subprocess.Popen(pysslscan_cmd, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
        result_stdout = result.stdout.read()
        pysslscan_ascii = os.system("sed 's/\x1b\[0m//g' " + request.folder + "private/pysslscan_ascii_esc.tmp " + \
                                    "> " + request.folder + "private/pysslscan_ascii_clean.tmp")
    #   clean_file = open(request.folder + "private/pysslscan_ascii_clean.tmp", "w")
    #   clean_file.write(str(pysslscan_ascii))
    #   clean_file.close()
        pysslscan_ascii_file = open(request.folder + "private/pysslscan_ascii_clean.tmp", "r")
    #   remove_tmp_files = os.system("rm -f " + request.folder + "private/pysslscan_ascii*.tmp")
        return dict(scan_result=pysslscan_ascii_file.read())
    else:
        return dict(scan_result="Nothing to report!")


@auth.requires_login()
def ping():
    import subprocess
    form = FORM('What IP address to \'PING\'? :',
                INPUT(_name='ipaddress', requires=IS_IPV4()),
                INPUT(_type='submit'))
    if form.process().accepted:
        session.flash = 'Input accepted'
        session.vars = form.vars
        # trace = os.popen('ping ' + '-c 2 '+ str(session.vars.ipaddress))
        try:
            timeout = "Ping timeout. Host not pingable or down."
            ping = subprocess.check_output('ping ' + '-c 3 ' + str(session.vars.ipaddress), shell=True)
            session.vars = ping.split('\n')
            #session.vars = ping
            #x = type(session.vars)
            #print(x)
        except subprocess.CalledProcessError as e:
            ret = e.returncode
            if ret == 1 or ret == 2:
                session.vars = timeout.split('\n')
        # print(session.vars)
        # trace.close()
        redirect(URL('ping_output'))
    elif form.errors:
        response.flash = 'Input has errors'
    else:
        response.flash = 'Please enter a valid IPv4 address.'
    # welcome_message_traceroute = "Welcome to the TRACEROUTE Tool!"
    return dict(form=form)


@auth.requires_login()
def ping_output():
    return dict(output=session.vars)


@auth.requires_login()
def traceroute():
    import subprocess
    form=FORM('What IP address to \'TRACEROUTE\'? :',
                INPUT(_name='ipaddress', requires=IS_IPV4()),
                INPUT(_type='submit'))
    if form.process().accepted:
        session.flash = 'Input accepted'
        session.vars=form.vars
        #trace = os.popen('ping ' + '-c 2 '+ str(session.vars.ipaddress))
        try:
            timeout = "Ping timeout. Host not pingable or down."
            trace = subprocess.check_output('traceroute ' + str(session.vars.ipaddress), shell=True)
            session.vars = trace.split('\n')
        except subprocess.CalledProcessError as e:
            ret = e.returncode
            if ret == 1 or ret == 2:
                session.vars = timeout.split('\n')
        #print(session.vars)
        #trace.close()
        redirect(URL('traceroute_output'))
    elif form.errors:
        response.flash = 'Input has errors'
    else:
        response.flash = 'Please enter a valid IPv4 address.'
    #welcome_message_traceroute = "Welcome to the TRACEROUTE Tool!"
    return dict(form=form)


@auth.requires_login()
def traceroute_output():
    return dict(output=session.vars)


@auth.requires_login()
def whois():
    import httplib
    #import subprocess
    form = FORM('What IP address to \'WHOIS\'? :',
                INPUT(_name='ipaddress', requires=IS_IPV4()),
                INPUT(_type='submit'))
    if form.process().accepted:
        session.flash = 'Input accepted'
        session.vars = form.vars
        try:
            uri = 'whois.arin.net'
            url = '/rest/ip/' + str(session.vars.ipaddress)
            print(url)
            headers = {"Content-type": "application/text",
                       "Accept": "text/html"}
            conn = httplib.HTTPConnection(uri, timeout=10)
            conn.request('GET', url, '' , headers)
            result = conn.getresponse()
            session.vars = result.read()
        except httplib.HTTPException as ex:
            session.vars = ex
            conn.close()
        print(session.vars)
        redirect(URL('whois_output'))
    elif form.errors:
        response.flash = 'Input has errors'
    else:
        response.flash = 'Please enter a valid IPv4 address.'
    # welcome_message_traceroute = "Welcome to the TRACEROUTE Tool!"
    return dict(form=form)


@auth.requires_login()
def whois_output():
    return dict(output=session.vars)


def error():
    error_message = "Ooooops, I am sorry....something went terribly wrong.....please try again."
    return dict(message=error_message)
