#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Usage: python pyDNSdump.py [dnsserver] [target] [recordtype]
#

import socket
import sys
import time
import mylibs.dnslib

def main():
    argv = sys.argv
    argc = len(argv)

    if argc < 3:
        print_exit(argv[0])

    target = argv[2]

    if argc < 4:
        recordtype = "ANY"
    else:
        recordtype = argv[3]

    recordtype = recordtype.upper()

    if mylibs.dnslib.is_ipv4_addr(target):
        ipaddr = target.split(".")
        target = ipaddr[3] + "." + ipaddr[2] + "." + ipaddr[1] + "." + ipaddr[0] + ".in-addr.arpa"

    if recordtype == "PTR" and ".in-addr.arpa" not in target:
        print("\"in-addr.arpa\" not in {0}".format(target))
        exit(1)

    dnsserver = argv[1]
    PORT = 53
    print("============================================================================================\n"
          "DNS Server    = {0}:{1:d}\n"
          "target        = {2}\n" 
          "record type   = {3}".format(dnsserver, PORT, target, recordtype))

    data_send = mylibs.dnslib.set_data(1, target, recordtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send a DNS udp request.
    s.sendto(data_send, (dnsserver, PORT))
    time_start = time.time()

    # recv a DNS udp response.
    data_recv, address = s.recvfrom(8192)
    time_end = time.time()
    s.close()

    # display results.
    print("============================================================================================\n"
          "Reply from    : {0}:{1}\n"
          "length        : 0x{2:04x}({3:d}) bytes.\n"
          "Response time : {4:f}[ms]\n"
          "============================================================================================"
        .format(address[0], address[1], len(data_recv), len(data_recv), (time_end - time_start)*1000))

    readbytes_count = mylibs.dnslib.print_recv_data(data_recv)
    print("============================================================================================")

    if readbytes_count == len(data_recv):
        print("Reception is complete.\n")
    else:
        print("There is a reading error.\n")


def print_exit(argv0):
    print("Usage: python {cmd} [dnsserver] [target] [recordtype]\n"
          "\n"
          "For Example)\n"
          "python {cmd} 192.168.1.1 www.hackerzlab.com cname\n"
          "python {cmd} 192.168.1.1 hackerzlab.com ns\n"
          "python {cmd} 192.168.1.1 hackerzlab.com mx\n"
          "python {cmd} 192.168.1.1 hackerzlab.com soa\n".format(cmd = argv0))
    exit(0)


if __name__ == "__main__":
    main()
