import pprint
# from googleapiclient.discovery import build
import optparse
import time
import sys
import os
import sqlite3
from sqlite3 import Error
import re
import threading
import datetime
import random
import json
import psutil
import psycopg2
import string
import subprocess
import urllib.parse
from bs4 import BeautifulSoup
from datetime import timezone
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from urllib3.exceptions import InsecureRequestWarning


# from some import HOSTS
# example
HOSTS = [
    ('блабла1.ру', 443),
    ('bal.bla.com', 443),
]



try:
    import requests
except ImportError:
    if sys.platform.startswith('linux'):
        print(" please install requests  module in Debian")
        sys.exit(" sudo apt-get install python-requests ")
    else:
        print(" install requets module for python here : https://pypi.python.org/pypi/requests/2.9.1 or try: pip install requests")
        sys.exit()

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna

from socket import socket
from collections import namedtuple

HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')



def verify_cert(cert, hostname):
    # verify notAfter/notBefore, CA trusted, servername/sni/hostname
    cert.has_expired()
    # service_identity.pyopenssl.verify_hostname(client_ssl, hostname)
    # issuer

def get_certificate(hostname, port):
    try:
        hostname_idna = idna.encode(hostname)
        sock = socket()

        sock.connect((hostname, port))
        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE

        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(hostname_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()

        return HostInfo(cert=crypto_cert, peername=peername, hostname=hostname)

    except Exception as err:
     print("Error occured while executing command: %s" % str(err))
     return False

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def print_basic_info(hostinfo):
    s = '''» {hostname} « … {peername}
    \tcommonName: {commonname}
    \tSAN: {SAN}
    \tissuer: {issuer}
    \tnotBefore: {notbefore}
    \tnotAfter:  {notafter}
    '''.format(
            hostname=hostinfo.hostname,
            peername=hostinfo.peername,
            commonname=get_common_name(hostinfo.cert),
            SAN=get_alt_names(hostinfo.cert),
            issuer=get_issuer(hostinfo.cert),
            notbefore=hostinfo.cert.not_valid_before,
            notafter=hostinfo.cert.not_valid_after
    )
    print(s)

def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


i=0
import concurrent.futures
if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e:
        for hostinfo in e.map(lambda x: get_certificate(x[0], x[1]), HOSTS):
            print((HOSTS[i]))
            i=i+1
            if hostinfo:
             print_basic_info(hostinfo)
