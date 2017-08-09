#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Copyright (c) 2010-2014 Develer S.r.L
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#

import argparse
import netaddr
import os
import os.path
import re
import signal
import socket
import sys
import syslog
import time
import MySQLdb
import MySQLdb.cursors

RE_IP = re.compile(r"\[(\d+)\.(\d+)\.(\d+)\.(\d+)\]")

def log(s):
    syslog.syslog(syslog.LOG_INFO, s)

def error(s):
    syslog.syslog(syslog.LOG_ERR, s)

class Database():

    def __init__(self, host, user, passwd, db):
        try:
           self.con = MySQLdb.Connect(host, user, passwd, db, cursorclass = MySQLdb.cursors.DictCursor)
           self.cur = self.con.cursor()
        except MySQLdb.Error, e:
           error("Can't connect to database: %s" % e)
           sys.exit(1)

    def clean_db(self):
           query = """DELETE FROM greylist WHERE epoch < (UNIX_TIMESTAMP() - {});""".format(MAX_GREYLIST_TIME)
           self.con.query(query)
           self.con.commit()

    def check_db(self, ip):
           query = """select ipv4addr,epoch from greylist where ipv4addr = '{}';""".format(ip)
           count = self.cur.execute(query)
           if count > 0:
               result_set = self.cur.fetchall()
               for row in result_set:
                   return time.time() - row["epoch"]
           return -1

    def add_db(self, ip):
           query = """insert into greylist (ipv4addr, epoch) values ('{}',UNIX_TIMESTAMP(now()));""".format(ip)
           self.con.query(query)
           self.con.commit()

def main():
    # Allow SIGPIPE to kill our program
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    args = parse_args()
    
    load_config_file(args.config)

    # Configure syslog support
    syslog.openlog("rblgrey", syslog.LOG_PID, getattr(syslog, SYSLOG_FACILITY))

    db = Database(HOST, USER, PASSWORD, DB)
    db.clean_db()

    process_one(db)

def parse_args():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-c", "--config", type=str, default="/etc/rblgrey.conf", help="path to the configuration file")

    return arg_parser.parse_args()


def load_config_file(config):
    try:
        execfile(config, globals())
    except Exception, e:
        # We can't use die() here
        syslog.openlog("rblgrey", syslog.LOG_PID)
        error("Error parsing configuration: %s" % e)
        sys.exit(2)

def die(s):
    error(s)
    sys.exit(2)


def process_one(db):
    d = {}

    while 1:
        L = sys.stdin.readline()
        L = L.strip()

        if not L:
            break
        try:
            k, v = L.split('=', 1)
        except ValueError:
            die("invalid input line: %r" % L)

        d[k.strip()] = v.strip()

    try:
        ip = d['client_address']
        helo = d['helo_name']
    except KeyError:
        die("client_address/helo_name field not found in input data, aborting")

    if not ip:
        die("client_address empty in input data, aborting")

    log("Processing client: S:%s H:%s" % (ip, helo))

    action = process_ip(ip, helo, db)

    log("Action for IP %s: %s" % (ip, action))
    sys.stdout.write('action=%s\n\n' % action)


def process_ip(ip, helo, db):
    if check_whitelist(ip):
        log("%s is whitelisted" % ip)
        return "ok Greylisting OK"
    if not check_rbls(ip) and not check_badhelo(helo):
        return "ok Greylisting OK"

    t = db.check_db(ip)

    if t < 0:
        log("%s not in greylist DB, adding it" % ip)

        db.add_db(ip)

        return "451 4.7.1 Greylisting in action, please try later."
    elif t < MIN_GREYLIST_TIME * 60:
        log("%s too young in greylist DB" % ip)

        return "451 4.7.1 Greylisting in action, please try later."
    else:
        log("%s already present greylist DB" % ip)

        return "ok Greylisting OK"


def check_rbls(ip):
    """True if the IP is listed in RBLs"""
    return any(query_rbl(ip, r) for r in RBLS)


def query_rbl(ip, rbl_root):
    addr_parts = list(reversed(ip.split('.'))) + [rbl_root]
    check_name = ".".join(addr_parts)

    try:
        ip = socket.gethostbyname(check_name)
    except socket.error:
        return None
    else:
        log("Found in blacklist %s (resolved to %s)" % (rbl_root, ip))

        return ip

def check_whitelist(ip):
    """True if the IP is whitelisted"""
    if len(GREYLIST_WHITELIST) > 0:
        wl = open(GREYLIST_WHITELIST)
        nip = netaddr.IPAddress(ip)
        for subnet in wl:
            if nip in netaddr.IPNetwork(subnet):
                wl.close()
                return True
        wl.close()

    return False

def check_badhelo(helo):
    """True if the HELO string violates the RFC"""
    if not CHECK_BAD_HELO:
        return False

    if helo.startswith('['):
        m = RE_IP.match(helo)

        if m is not None:
            octs = map(int, (m.group(1), m.group(2), m.group(3), m.group(4)))

            if max(octs) < 256:
                return False

        log("HELO string begins with '[' but does not contain a valid IPv4 address")

        return True

    if '.' not in helo:
        log("HELO string does not look like a FQDN")

        return True

    return False

# def clean_db(ip):
#     os.remove(os.path.join(GREYLIST_DB, ip))

if __name__ == "__main__":
    main()
