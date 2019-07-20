#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket

def main():
    # "or.jp" "any"
    # data_send = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02or\x02jp\x00\x00\xff\x00\x01'
    # "." "ns"
    # data_send = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'
    data_send = set_Header_and_Question(1, "jp", "ns")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send a DNS udp request.
    s.sendto(data_send, ("8.8.8.8", 53))

    # recv a DNS udp response.
    data_recv, address = s.recvfrom(8192)

    # print(data_recv)
    print("DNS Response from {0}".format(address))
    for i in range(len(data_recv)):
        if i % 16 == 0:
            print("\n{0:04x}: {1:02x}".format(i, data_recv[i]), end = "")
        else:
            print(" {0:02x}".format(data_recv[i]), end = "")

def set_Header_and_Question(Transaction_ID, resolvstring, type):
    data = Transaction_ID.to_bytes(2, 'big')    # Transaction ID
    data += 0x0100.to_bytes(2, 'big')           # Flags
    data += 0x0001.to_bytes(2, 'big')           # Questions
    data += 0x0000.to_bytes(2, 'big')           # Answer RRS
    data += 0x0000.to_bytes(2, 'big')           # Answer RRS
    data += 0x0000.to_bytes(2, 'big')           # Additional RRS

    # Queries
    if resolvstring == ".":
        data += 0x00.to_bytes(1, 'big')
    else:
        flds = resolvstring.split(".")
        for name in flds:
            data += len(name).to_bytes(1, 'big')
            data += name.encode(encoding = 'ascii')
        data += 0x00.to_bytes(1, 'big')
    data += set_RecordType(type.upper())        # Type
    data += 0x0001.to_bytes(2, 'big')           # Class ... IN(0x0001)

    return data

def set_RecordType(type):
    if type.isnumeric() == True:
        if int(type) > 0:
            return int(type).to_bytes(2, 'big')

    # Type
    if type == None:
        return 0x00ff.to_bytes(2, 'big')
    elif type == 'A':
        return 0x0001.to_bytes(2, 'big')
    elif type == 'NS':
        return 0x0002.to_bytes(2, 'big')
    elif type == 'CNAME':
        return 0x0005.to_bytes(2, 'big')
    elif type == 'SOA':
        return 0x0006.to_bytes(2, 'big')
    elif type == 'PTR':
        return 0x000c.to_bytes(2, 'big')
    elif type == 'HINFO':
        return 0x000d.to_bytes(2, 'big')
    elif type == 'MX':
        return 0x000f.to_bytes(2, 'big')
    elif type == 'TXT':
        return 0x0010.to_bytes(2, 'big')
    elif type == 'AAAA':
        return 0x001c.to_bytes(2, 'big')
    elif type == 'SRV':
        return 0x0021.to_bytes(2, 'big')
    elif type == 'DS':
        return 0x002b.to_bytes(2, 'big')
    elif type == 'RRSIG':
        return 0x002e.to_bytes(2, 'big')
    elif type == 'NSEC':
        return 0x002f.to_bytes(2, 'big')
    elif type == 'DNSKEY':
        return 0x0030.to_bytes(2, 'big')
    elif type == 'NSEC3':
        return 0x0032.to_bytes(2, 'big')
    elif type == 'NSEC3PARAM':
        return 0x0033.to_bytes(2, 'big')
    elif type == 'CAA':
        return 0x0101.to_bytes(2, 'big')
    elif type == 'ANY':
        return 0x00ff.to_bytes(2, 'big')
    else:
        return 0x00ff.to_bytes(2, 'big')

if __name__ == "__main__":
    main()
