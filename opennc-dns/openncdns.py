#!/usr/bin/python3


import sqlite3
import requests
import configparser
import logging
import sys
import os
import time
import json
import socket
import socket
import secrets

from dnslib import DNSLabel, QTYPE, RR, dns, DNSRecord
from dnslib.proxy import ProxyResolver
from dnslib.server import DNSServer


version = "0.2.0"
records = []
cache = []
zones = {}


TYPE_LOOKUP = {
    'A': (dns.A, QTYPE.A),
    'AAAA': (dns.AAAA, QTYPE.AAAA),
    'CAA': (dns.CAA, QTYPE.CAA),
    'CNAME': (dns.CNAME, QTYPE.CNAME),
    'DNSKEY': (dns.DNSKEY, QTYPE.DNSKEY),
    'MX': (dns.MX, QTYPE.MX),
    'NAPTR': (dns.NAPTR, QTYPE.NAPTR),
    'NS': (dns.NS, QTYPE.NS),
    'PTR': (dns.PTR, QTYPE.PTR),
    'RRSIG': (dns.RRSIG, QTYPE.RRSIG),
    'SOA': (dns.SOA, QTYPE.SOA),
    'SRV': (dns.SRV, QTYPE.SRV),
    'TXT': (dns.TXT, QTYPE.TXT),
    'SPF': (dns.TXT, QTYPE.TXT),
}


QTYPE_LOOKUP = {
    1: ("A", dns.A),
    28: ("AAAA", dns.AAAA),
    257: ("CAA", dns.CAA),
    5: ("CNAME", dns.CNAME),
    48: ("DNSKEY", dns.DNSKEY),
    15: ("MX", dns.MX),
    35: ("NAPTR", dns.NAPTR),
    2: ("NS", dns.NS),
    12: ("PTR", dns.PTR),
    46: ("RRSIG", dns.RRSIG),
    6: ("SOA", dns.SOA),
    33: ("SRV", dns.SRV),
    16: ("TXT", dns.TXT),
    99: ("SPF", dns.TXT)
}


class Record:
    def __init__(self, rname, rtype, args):
        self.rname = DNSLabel(rname)
        rd_cls, self.rtype = TYPE_LOOKUP[rtype]

        self.rr = RR(rname=self.rname, rtype=self.rtype, rdata=rd_cls(*args), ttl=0)

    def match(self, q):
        return q.qname == self.rname and (q.qtype == QTYPE.ANY or q.qtype == self.rtype)


class Resolver(ProxyResolver):
    def __init__(self, mode):
        super().__init__("8.8.8.8", 53, timeout=timeout)
        self.mode = mode


    def resolve(self, request, handler):
        reply = request.reply()
        logger.debug("New DNS request: %s type %s" % (request.q.qname, request.q.qtype))
        #reply.add_answer(RR(rname=DNSLabel("google.com"), rtype=QTYPE.A, rdata=dns.A("8.8.8.8")))
        # If serving current zones
        for i in records:
            if i.match(request.q):
                reply.add_answer(i.rr)
        if self.mode == "authoritative":
            return reply
        else:
            # If alredy know this record
            for i in cache:
                if i.match(request.q):
                    reply.add_answer(i.rr)
            if reply.rr:
                return reply
            # Making recursive request
            for i in zones:
                if str(request.q.qname).endswith(i):
                    logger.debug("DNS reqursive request to %s" % zones[i])
                    resp = dnsrequest(request.q.qname, request.q.qtype, zones[i])
                    if resp:
                        record = Record(request.q.qname, QTYPE_LOOKUP[request.q.qtype][0], [resp])
                        cache.append(record)
                        reply.add_answer(record.rr)
                    return reply
            else:
                if "default" in zones:
                    logger.debug("DNS reqursive request to default server %s" % zones["default"])
                    resp = dnsrequest(str(request.q.qname), request.q.qtype, zones["default"])
                    if resp:
                        record = Record(request.q.qname, QTYPE_LOOKUP[request.q.qtype][0], [resp])
                        cache.append(record)
                        reply.add_answer(record.rr)
                    return reply
                else:
                    logger.warning("All default servers unavaluable")
                    return super().resolve(request, handler)


# Read config and return params
class Config:
    def __init__(self, path_to_config):
        try:
            conf_str = "[default]\n" + open(path_to_config, "r").read().replace("[", "").replace("]", "")
            self.configparser = configparser.RawConfigParser()
            self.configparser.read_string(conf_str)
        except Exception as e:
            self.configparser = None
    
    def get(self, param_name, replacement=None):
        if self.configparser:
            section="default"
            if self.configparser.has_section(section) and self.configparser.has_option(section, param_name):
                return self.configparser.get(section, param_name)
            else:
                return replacement
        else:
            return replacement


def setlogging(path_to_log, log_level):
    #logging.basicConfig(filename=path_to_log, level=logging._nameToLevel(log_level))
    logger = logging.getLogger()
    logger.setLevel(logging._nameToLevel[log_level])
    lfh = logging.FileHandler(path_to_log)
    lformatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    lfh.setFormatter(lformatter)
    logger.addHandler(lfh)
    return logger


def initdb(path_to_db):
    conn = sqlite3.connect(path_to_db)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS zones(id INTEGER PRIMARY KEY, name TEXT, server TEXT);''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS cache(id INTEGER PRIMARY KEY, name TEXT, type TEXT, args TEXT);''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS servezones(id INTEGER PRIMARY KEY, name TEXT, type TEXT, args TEXT);''')
    conn.commit()
    cursor.execute('''SELECT name, server FROM zones;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if i[0] == "" or i[0] == "." or i[0] == "default":
            i[0] = "default"
        elif not i[0].endswith("."):
            i[0] += "."
        i[0] = i[0].replace("*.", "")
        zones[i[0]] = i[1]
    cursor.execute('''SELECT name, type, args FROM servezones;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if not i[0].endswith("."):
            i[0] += "."
        records.append(Record(i[0], i[1], [i[2]]))
    cursor.execute('''SELECT name, type, args FROM cache;''')
    result = cursor.fetchall()
    for i in result:
        i = list(i)
        if not i[0].endswith("."):
            i[0] += "."
        cache.append(Record(i[0], i[1], [i[2]]))
    conn.close()


def dnsrequest(rname, rtype, server):
    if "https" in server or "doh" in server:
        try:
            params={"name": rname, "type": rtype}
            headers={"accept": "application/dns-json"}
            resp = requests.get("https://" + server.split("://")[1], params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200 and resp.json()["Status"] == 0:
                return resp.json()["Answer"][0]["data"]
            else:
                logger.warning("Failed to execute DOH request (%s): %s" % (resp.status_code, resp.content))
        except Exception as e:
            logger.warning("Failed to execute DOH request: " + str(e))
    else:
        resp = request_classic(str(rname), server, rtype, timeout=timeout)
        if resp[0] == 0:
            return resp[1][0][3]
        else:
            logger.warning("Failed to execute classic DNS request: " + resp)


def request_classic(name, server, qtype=1, port=53, timeout=1):  # A 1, NS 2, CNAME 5, SOA 6, NULL 10, PTR 12, MX 15, TXT 16, AAAA 28, NAPTR 35, * 255
    addr=(server, port)
    name = name.rstrip('.')
    queryid = secrets.token_bytes(2)
    # Header. 1 for Recursion Desired, 1 question, 0 answers, 0 ns, 0 additional
    request = queryid + b'\1\0\0\1\0\0\0\0\0\0'
    # Question
    for label in name.rstrip('.').split('.'):
        assert len(label) < 64, name
        request += int.to_bytes(len(label), length=1, byteorder='big')
        request += label.encode()
    request += b'\0'  # terminates with the zero length octet for the null label of the root.
    request += int.to_bytes(qtype, length=2, byteorder='big')  # QTYPE
    request += b'\0\1'  # QCLASS = 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(request, addr)
        s.settimeout(timeout)
        try:
            response, serveraddr = s.recvfrom(4096)
        except socket.timeout:
            raise TimeoutError(name, timeout)
    assert serveraddr == addr, (serveraddr, addr)
    assert response[:2] == queryid, (response[:2], queryid)
    assert response[2] & 128  # QR = Response
    assert not response[2] & 4  # No Truncation
    assert response[3] & 128  # Recursion Available
    error_code = response[3] % 16  # 0 = no error, 1 = format error, 2 = server failure, 3 = does not exist, 4 = not implemented, 5 = refused
    qdcount = int.from_bytes(response[4:6], 'big')
    ancount = int.from_bytes(response[6:8], 'big')
    assert qdcount <= 1
    # parse questions
    qa = response[12:]
    for question in range(qdcount):
        domain, qa = parse_qname(qa, response)
        qtype, qa = parse_int(qa, 2)
        qclass, qa = parse_int(qa, 2)
    # parse answers
    answers = []
    for answer in range(ancount):
        domain, qa = parse_qname(qa, response)
        qtype, qa = parse_int(qa, 2)
        qclass, qa = parse_int(qa, 2)
        ttl, qa = parse_int(qa, 4)
        rdlength, qa = parse_int(qa, 2)
        rdata, qa = qa[:rdlength], qa[rdlength:]
        if qtype == 1:  # IPv4 address
            rdata = '.'.join(str(x) for x in rdata)
        if qtype == 15:  # MX
            mx_pref, rdata = parse_int(rdata, 2)
        if qtype in (2, 5, 12, 15):  # NS, CNAME, MX
            rdata, _ = parse_qname(rdata, response)
        answer = (qtype, domain, ttl, rdata, mx_pref if qtype == 15 else None)
        answers.append(answer)
    return error_code, answers


def parse_int(byts, ln):
    return int.from_bytes(byts[:ln], 'big'), byts[ln:]


def parse_qname(byts, full_response):
    domain_parts = []
    while True:
        if byts[0] // 64:  # OFFSET pointer
            assert byts[0] // 64 == 3, byts[0]
            offset, byts = parse_int(byts, 2)
            offset = offset - (128 + 64) * 256  # clear out top 2 bits
            label, _ = parse_qname(full_response[offset:], full_response)
            domain_parts.append(label)
            break
        else:  # regular QNAME
            ln, byts = parse_int(byts, 1)
            label, byts = byts[:ln], byts[ln:]
            if not label:
                break
            domain_parts.append(label.decode())
    return '.'.join(domain_parts), byts


if __name__ == "__main__":
    # Return help and exit
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: %s [OPTIONS]" % sys.argv[0])
        print("Start OpenNC DNS server.\n")
        print("-c             path to the configuration file")
        print("-h, --help     display this help and exit")
        print("-v, --version  output version information and exit")
        print("-p, --port     set listening port")
        print()
        print("Full documentation and source code avaluable on https://github.com/qerty123/OpenNC") 
        print("Project distributed under GUN GPLv3 license https://www.gnu.org/licenses/gpl-3.0.html \n")
        exit()


    # Return version and exit
    if "-v" in sys.argv or "--version" in sys.argv:
        print(version)
        exit()

    # Getting settings from config file
    if "-c" in sys.argv:
        path_to_conf = sys.argv[sys.argv.index("-c") + 1]
    else:
        path_to_conf = "/etc/opennc/opennc-dns.conf" 

    if os.path.exists(path_to_conf):
        config = Config(path_to_conf)
    else:
        print("No such file or directory " + path_to_conf)
        exit()

    # Init logging
    path_to_log = config.get("log", "/var/log/opennc/opennc-dns.log")
    log_level = config.get("log_level", "WARNING")
    logger = setlogging(path_to_log, log_level)

    # Init database
    initdb(config.get("database", "/etc/opennc/opennc-dns.db"))

    # Set listening port
    if "-p" in sys.argv:
        port = int(sys.argv[sys.argv.index("-p") + 1])
    elif "--port" in sys.argv:
        port = int(sys.argv[sys.argv.index("--port") + 1])
    else:
        port = int(config.get("port", "53"))

    timeout = int(config.get("timeout", "5"))

    resolver = Resolver(config.get("mode", "recursive"))
    if "udp" in config.get("protocol", "TCP, UDP").lower():
        udp_server = DNSServer(resolver, port=port)    
        udp_server.start_thread()
    if "tcp" in config.get("protocol", "TCP, UDP").lower():
        tcp_server = DNSServer(resolver, port=port, tcp=True) 
        tcp_server.start_thread()

    logger.info("DNS server started on port %s" % port)

    # Serving DNS requests
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass



