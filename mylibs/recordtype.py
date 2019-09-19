# -*- coding: utf-8 -*-

type_list = {}

def set_type_list():
    """
    RFC 1035
    https://www.ietf.org/rfc/rfc1035.txt

    Wikipedia - List of DNS record type
    https://ja.wikipedia.org/wiki/DNS%E3%83%AC%E3%82%B3%E3%83%BC%E3%83%89%E3%82%BF%E3%82%A4%E3%83%97%E3%81%AE%E4%B8%80%E8%A6%A7
    """
    type_list['A'] = 0x0001.to_bytes(2, 'big')          # 1
    type_list['NS'] = 0x0002.to_bytes(2, 'big')         # 2
    type_list['CNAME'] = 0x0005.to_bytes(2, 'big')      # 5
    type_list['SOA'] = 0x0006.to_bytes(2, 'big')        # 6
    type_list['PTR'] = 0x000c.to_bytes(2, 'big')        # 12
    type_list['HINFO'] = 0x000d.to_bytes(2, 'big')      # 13
    type_list['MX'] = 0x000f.to_bytes(2, 'big')         # 15
    type_list['TXT'] = 0x0010.to_bytes(2, 'big')        # 16
    type_list['AAAA'] = 0x001c.to_bytes(2, 'big')       # 28
    type_list['SRV'] = 0x0021.to_bytes(2, 'big')        # 33
    type_list['DS'] = 0x002b.to_bytes(2, 'big')         # 43
    type_list['RRSIG'] = 0x002e.to_bytes(2, 'big')      # 46
    type_list['NSEC'] = 0x002f.to_bytes(2, 'big')       # 47
    type_list['DNSKEY'] = 0x0030.to_bytes(2, 'big')     # 48
    type_list['NSEC3'] = 0x0032.to_bytes(2, 'big')      # 50
    type_list['NSEC3PARAM'] = 0x0033.to_bytes(2, 'big') # 51
    type_list['CAA'] = 0x0101.to_bytes(2, 'big')        # 257
    type_list['ANY'] = 0x00ff.to_bytes(2, 'big')        # 255


def set_RecordType(type_name):
    if type_name.isnumeric() == True:
        if int(type_name) > 0:
            return int(type_name).to_bytes(2, 'big')

    if type_name in type_list.keys():
        return type_list[type_name]
    else:
        return 0x00ff.to_bytes(2, 'big')


def get_RecordType(type_val):
    target_type_val = type_val.to_bytes(2, 'big')

    if target_type_val in type_list.values():
        # return the first one found.
        return [key for key, val in type_list.items() if val == target_type_val][0]
    else:
        return ""
