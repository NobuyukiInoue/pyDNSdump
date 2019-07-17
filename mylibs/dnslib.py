# -*- coding: utf-8 -*-

def is_ipv4_addr(resolvstr):
    flds = resolvstr.split(".")
    if len(flds) != 4:
        return False
    for oct in flds:
        if not oct.isdecimal():
            return False
        if int(oct) < 0 or int(oct) > 255:
            return False
    return True


def set_data(Transaction_ID, resolvstring, type):
    # Transaction ID
    data = Transaction_ID.to_bytes(2, 'big')

    # Flags
    data += 0x0100.to_bytes(2, 'big')

    # Questions
    data += 0x0001.to_bytes(2, 'big')

    # Answer RRS
    data += 0x0000.to_bytes(2, 'big')

    # Answer RRS
    data += 0x0000.to_bytes(2, 'big')

    # Additional RRS
    data += 0x0000.to_bytes(2, 'big')

    # Queries
    if resolvstring == ".":
        data += 0x00.to_bytes(1, 'big')
    else:
        flds = resolvstring.split(".")
        for name in flds:
            data += len(name).to_bytes(1, 'big')
            data += name.encode(encoding = 'ascii')
        data += 0x00.to_bytes(1, 'big')

    # Type
    data += set_type(type)

    # Class ... IN(0x0001)
    data += 0x0001.to_bytes(2, 'big')

    return data


def set_type(type):
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


def get_type(int_type):
    """
    RFC 1035
    https://www.ietf.org/rfc/rfc1035.txt

    Wikipedia - List of DNS record type
    https://ja.wikipedia.org/wiki/DNS%E3%83%AC%E3%82%B3%E3%83%BC%E3%83%89%E3%82%BF%E3%82%A4%E3%83%97%E3%81%AE%E4%B8%80%E8%A6%A7
    """
    if int_type == 255:
        return "ANY"
    elif int_type == 1:
        return "A"
    elif int_type == 2:
        return "NS"
    elif int_type == 5:
        return "CNAME"
    elif int_type == 6:
        return "SOA"
    elif int_type == 12:
        return "PTR"
    elif int_type == 13:
        return "HINFO"
    elif int_type == 15:
        return "MX"
    elif int_type == 16:
        return "TXT"
    elif int_type == 28:
        return "AAAA"
    elif int_type == 33:
        return "SRV"
    elif int_type == 43:
        return "DS"
    elif int_type == 46:
        return "RRSIG"
    elif int_type == 47:
        return "NSEC"
    elif int_type == 48:
        return "DNSKEY"
    elif int_type == 50:
        return "NSEC3"
    elif int_type == 51:
        return "NSEC3PARAM"
    elif int_type == 257:
        return "CAA"
    else:
        return ""


def get_class(int_class):
    """
    RFC 1035
    https://www.ietf.org/rfc/rfc1035.txt
    """
    if int_class == 1:
        return "IN"
    elif int_class == 2:
        return "CS"
    elif int_class == 3:
        return "CH"
    elif int_class == 4:
        return "HS"
    else:
        return ""


def get_dhms(ttl):
    day_seconds = 24*60*60
    d = ttl // day_seconds
    t = ttl % day_seconds
    ss = t % 60
    mm = t // 60
    hh = mm // 60
    mm = mm % 60
    return "{0:d} day {1:02d}:{2:02d}:{3:02d}".format(d, hh, mm, ss)


def get_algorithm(byte_algorithm):
    if byte_algorithm == 1:
        return ("MD5", 128)
    elif byte_algorithm == 5:
        return ("SHA1", 160)
    elif byte_algorithm == 8:
        return ("SHA256", 256)
    elif byte_algorithm == 10:
        return ("SHA512", 512)
    else:
        return ("", 0)


def get_dnskey_protocol(Protocol):
    if Protocol == 3:
        return "DNSKEY"
    else:
        return ""


def get_digest_type(digest_type):
    if digest_type == 0:
        return "Reserved"
    if digest_type == 1:
        return "SHA1"
    if digest_type == 2:
        return "SHA256"
    if digest_type == 3:
        return "GOST R 34.11-94"
    if digest_type == 4:
        return "SHA-384"
    else:
        return "Unassigned"


def get_NSEC3_Hash_algorithm(byte_algorithm):
    if byte_algorithm == 0:
        return "Reserved"
    elif byte_algorithm == 1:
        return "SHA1"
    else:
        return "Available for assignment"


def get_stripv6addr(addr):
    result = ""
    for i in range(0, len(addr), 2):
        word = (addr[i] << 8) + addr[i + 1]
        if word == 0:
            if i > 0:
                if result[-1] != ":":
                    result += ":"
            else:
                result += ":"
        elif i == 0:
            result = "{0:x}".format(word)
        else:
            result += ":{0:x}".format(word)
    return result


def print_recv_data(data):
    print("{0:04x}: {1:13} {2:<16}".format(0, "", "Header:"))
    fld_Transaction_ID = (data[0] << 8) + data[1]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(0, fld_Transaction_ID, "", "Transaction ID:", fld_Transaction_ID))

    fld_Flags = (data[2] << 8) + data[3]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4}".format(2, fld_Flags, "", "Flags:", bin(fld_Flags)))
    print_flags(fld_Flags)

    fld_Question = (data[4] << 8) + data[5]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(4, fld_Question, "", "Questions:", fld_Question))

    fld_Anser_RRS = (data[6] << 8) + data[7]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(6, fld_Anser_RRS, "", "Answer RRS:", fld_Anser_RRS))

    fld_Authority_RRS = (data[8] << 8) + data[9]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(8, fld_Authority_RRS, "", "Authority RRS:", fld_Authority_RRS))

    fld_Additional_RRS = (data[10] << 8) + data[11]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(10, fld_Additional_RRS, "", "Additional RRS:", fld_Additional_RRS))

    i = 12
    print("\n"
          "{0:04x}: {1:13} {2}".format(i, "", "Querys:"))
    # Name:
    i = print_name(data, "Name:", i)

    fld_type = (data[i] << 8) + data[i + 1]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4}({5:d})".format(i, fld_type, "", "Type:", get_type(fld_type), fld_type))
    i += 2

    fld_class = (data[i] << 8) + data[i + 1]
    print("{0:04x}: {1:04x} {2:8} {3:<24} {4}({5:d})".format(i, fld_class, "", "Class:", get_class(fld_class), fld_class))
    i += 2

    i = get_answer(data, i, "Answer", fld_Anser_RRS)
    i = get_answer(data, i, "Authority", fld_Authority_RRS)
    i = get_answer(data, i, "Additional", fld_Anser_RRS)

    return i


def print_flags(flags):
    print("/*")

    QR = (flags & 0x8000) >> 15
    label = "[bit 0]     QR"
    if QR == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, QR, "... Query"))
    elif QR == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, QR, "... Response"))

    OPCODE = (flags & 0x7800) >> 11
    label = "[bit 1-4]   OPCODE"
    if OPCODE == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, OPCODE, "... standard query"))
    elif OPCODE == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, OPCODE, "... inverse query"))
    elif OPCODE == 2:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, OPCODE, "... server status request"))

    AA = (flags & 0x0400) >> 10
    label = "[bit 5]     AA"
    if AA == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, AA, "... Not Authoritative"))
    elif AA == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, AA, "... Authoritative"))

    TC = (flags & 0x0200) >> 9
    label = "[bit 6]     TC"
    if TC == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, TC, "... Did not Flagment"))
    elif TC == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, TC, "... Flagment occur"))

    RD = (flags & 0x0100) >> 8
    label = "[bit 7]     RD"
    if RD == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RD, "... Recursion Query"))
    elif RD == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RD, "... Repeat Query"))

    RA = (flags & 0x0080) >> 7
    label = "[bit 8]     RA"
    if RA == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RA, "... Recursion Available is True"))
    elif RA == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RA, "... Recursion Available is False"))

    Reserve = (flags & 0x0040) >> 6
    label = "[bit 9]     Reserve"
    print("{0:21} {1:<20}({2:d})".format("", label, Reserve))

    # bit 10	AD	Authentic Data	[RFC4035][RFC6840][RFC Errata 4924]
    AD = (flags & 0x0020) >> 5
    label = "[bit 10]    Authentic Data"
    print("{0:21} {1:<20}({2:d})".format("", label, AD))

    # bit 11	CD	Checking Disabled	[RFC4035][RFC6840][RFC Errata 4927]
    CD = (flags & 0x0010) >> 4
    label = "[bit 11]    Checking Disable"
    print("{0:21} {1:<20}({2:d})".format("", label, CD))

    RCODE = (flags & 0x000f)
    label = "[bit 12-15] RCODE"
    if RCODE == 0:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... No Error"))
    elif RCODE == 1:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... Format Error"))
    elif RCODE == 2:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... Server Error"))
    elif RCODE == 3:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... Name Error"))
    elif RCODE == 4:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... undefined"))
    elif RCODE == 5:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... Reject"))
    else:
        print("{0:21} {1:<20}({2:d}) {3}".format("", label, RCODE, "... (unknown)"))

    print("*/")


def print_name(data, title, i):
    fld_name, name_length = get_name(data, i)

    if data[i] == 0x00:
        print("{0:04x}: {1:02x} {2:10} {3:<24} {4:}".format(i, data[i], "", title, "<Root>"))
    else:
        if 2*name_length < 13:
            format_str = "{0:04x}: {1:0" + str(2*name_length) + "x} {2:" + str(13 - 2*name_length) + "}{3:<24} {4}"
        else:
            format_str = "{0:04x}: {1:0" + str(2*name_length) + "x} {2} {3:<24} {4}"
        print(format_str.format(i, int.from_bytes(data[i:i + name_length], 'big') , "", title, fld_name))

    i += name_length

    return i


def get_answer(data, i, title, record_length):
    record_count = 0
    while i < len(data) and record_count < record_length:
        print("\n"
              "{0:04x}: {1:13} {2}".format(i, "", title + "[" + str(record_count) + "]:"))

        result_bits = ((data[i] << 8) + data[i + 1]) & 0xC000

        if result_bits == 0xc000:
            name_hex = (data[i] << 8) + data[i + 1]
            result_pos = name_hex & 0x3fff
            fld_name, _ = get_name(data, result_pos)
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4}".format(i, int.from_bytes(data[i:i + 2], 'big') , "", "Name:", fld_name))
            i += 2

        elif result_bits == 0x8000:
            i += 2

        elif result_bits == 0x4000:
            i += 2

        elif data[i] == 0x00:
            print("{0:04x}: {1:02x} {2:10} {3:<24} <Root>".format(i, data[i], "", "Name:"))
            i += 1

        fld_type = (data[i] << 8) + data[i + 1]
        type_name = get_type(fld_type)
        print("{0:04x}: {1:04x} {2:8} {3:<24} {4}({5:d})".format(i, fld_type, "", "Type:", type_name, fld_type))
        i += 2

        fld_class = (data[i] << 8) + data[i + 1]
        print("{0:04x}: {1:04x} {2:8} {3:<24} {4}({5:d})".format(i, fld_class, "", "Class:", get_class(fld_class), fld_class))
        i += 2

        fld_ttl = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3] 
        print("{0:04x}: {1:08x} {2:4} {3:<24} {4}({5:d})".format(i, fld_ttl, "", "Time to live:", get_dhms(fld_ttl), fld_ttl))
        i += 4

        fld_data_length = (data[i] << 8) + data[i + 1]
        print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_data_length, "", "data_length:", fld_data_length))
        i += 2

        if type_name == "NS":
            # Name:
            i = print_name(data, "Name:",  i)

        elif type_name == "HINFO":
            # HINFO:
            i = print_name(data, "HINFO:", i)

        elif type_name == "MX":
            fld_Preference = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Preference, "", "fld_Preference:", fld_Preference))
            i += 2

            result, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big'), "", "Mail exchange:", result))
            i += result_length

        elif type_name == 'SOA':
            fld_primary_name_server, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big'), "", "Primary name server:", fld_primary_name_server))
            i += result_length

            fld_Responsivle_authoritys_mailbox, length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*length) + "x} \n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + length], 'big'), "", "Responsible authoritys mailbox:", fld_Responsivle_authoritys_mailbox))
            i += length

            Serial_number = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, Serial_number, "", "Serial number:", Serial_number))
            i += 4

            Refresh_interval = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08} {2:4} {3:<24} {4:}".format(i, Refresh_interval, "", "Refresh interval:", Refresh_interval))
            i += 4

            Retry_interval = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, Retry_interval, "", "Retry interval:", Retry_interval))
            i += 4

            Expiration_limit = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, Expiration_limit, "", "Expiration limit:", Expiration_limit))
            i += 4

            Minimum_TTL = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4}({5:d})".format(i, Minimum_TTL, "", "Minimum TTL:", get_dhms(Minimum_TTL), Minimum_TTL))
            i += 4

        elif type_name == 'A' or type_name == 'CNAME':
            if fld_data_length == 4:
                print("{0:04x}: {1:02x}{2:02x}{3:02x}{4:02x} {5:4} {6:<24} {7:d}.{8:d}.{9:d}.{10:d}".format(i, data[i], data[i + 1], data[i + 2], data[i + 3], "", "Addr:", data[i], data[i + 1], data[i + 2], data[i + 3]))
                i += 4
            else:
                result, result_length = get_name(data, i)
                format_str = "{0:04x}: {1:0" + str(2*result_length) + "x} \n {2:18} {3:<24} {4}"
                print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big'), "", "Primary name:", result))
                i += result_length

        elif type_name == "TXT":
            """
            # TXT:
            i = print_name(data, "TXT:", i)
            """
            fld_Text = data[i:i + fld_data_length]
            format_str = "{0:04}: {1:0" + str(2*len(fld_Text)) + "x} \n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(fld_Text, 'big'), "", "Text:", fld_Text))
            i += fld_data_length

        elif type_name == "RRSIG":
            i_start = i

            fld_Type_covered = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Type_covered, "", "Type covered:", fld_Type_covered))
            i += 2

            fld_Algorithm = data[i]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4}({5:d})".format(i, fld_Algorithm, "", "Algorithm:", get_algorithm(fld_Algorithm)[0], fld_Algorithm))
            i += 1

            fld_Labels = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4:d}".format(i, fld_Labels, "", "Labels:", fld_Labels))
            i += 1

            fld_Original_TTL = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4}({5:d})".format(i, fld_Original_TTL, "", "Original TTL:", get_dhms(fld_Original_TTL), fld_Original_TTL))
            i += 4

            fld_Signature_expiration = (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, fld_Signature_expiration, "", "fld_Signature_expiration:", fld_Signature_expiration))
            i += 4

            fld_Time_signed =  (data[i] << 24) + (data[i + 1] << 16) + (data[i + 2] << 8) + data[i + 3]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, fld_Time_signed, "", "Time signed:", fld_Time_signed))
            i += 4

            fld_Id_of_signing_key = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:08x} {2:4} {3:<24} {4:d}".format(i, fld_Id_of_signing_key, "", "Id of signing key:", fld_Id_of_signing_key))
            i += 2

            result, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big'), "", "Signer's name:", result))
            i += result_length

            signature_size = fld_data_length - (i - i_start)
            result, _ = get_signature(data, i, signature_size)
            format_str = "{0:04x}: {1:0" + str(2*signature_size) + "x}\n" + " {2:18} {3:<24}"
            print(format_str.format(i, int.from_bytes(data[i:i + signature_size], 'big'), "", "Signature:"), end = "")
            print_result(result)
            i += signature_size

        elif type_name == "DNSKEY":
            i_start = i

            fld_Flags = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4}".format(i, fld_Flags, "", "Flags:", fld_Flags))
            i += 2

            fld_Protocol = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4}({5:d})".format(i, fld_Protocol, "", "Protocol:", get_dnskey_protocol(fld_Protocol), fld_Protocol))
            i += 1

            fld_Algorithm = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4}({5:d})".format(i, fld_Algorithm, "", "Algorithm:", get_algorithm(fld_Algorithm)[0], fld_Algorithm))
            i += 1

            fld_public_key_length = fld_data_length - (i - i_start)
            fld_public_key = data[i:i + fld_public_key_length]
            format_str = "{0:04x}: {1:0" + str(2*fld_public_key_length) + "x}\n {2:18} {3:<24}"
            print(format_str.format(i, int.from_bytes(fld_public_key, 'big'), "", "Public Key:"), end = "")
            print_result_bin(fld_public_key)
            i += fld_public_key_length

        elif type_name == "NSEC":
            i_start = i

            # Next domain name:
            i = print_name(data, "Next domain name:", i)

            fld_bitmap_length = fld_data_length - (i - i_start)
            fld_bitmap = data[i:i + fld_bitmap_length]
            format_str = "{0:04x}: {1:0" + str(2*fld_bitmap_length) + "x}\n {2:18} {3:<24}"
            print(format_str.format(i, int.from_bytes(fld_bitmap, 'big'), "", "bit map:"), end = "")
            print_result_bin(fld_bitmap)
            i += fld_bitmap_length


        elif type_name == "NSEC3" or type_name == "NSEC3PARAM":
            i_start = i

            fld_Algorithm = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4}({5:d})".format(i, fld_Algorithm, "", "Hash Algorithm:", get_NSEC3_Hash_algorithm(fld_Algorithm), fld_Algorithm))
            i += 1

            fld_NSEC3_flags = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4:d}".format(i, fld_Algorithm, "", "NSEC3 flags:", fld_NSEC3_flags))
            i += 1

            fld_NSEC3_iterations = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_NSEC3_iterations, "", "NSEC3 iterations:", fld_NSEC3_iterations))
            i += 2

            fld_Salt_length = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4:d}".format(i, fld_Salt_length, "", "Salt length:", fld_Salt_length))
            i += 1

            fld_Salt_value = int.from_bytes(data[i:i + fld_Salt_length], 'big')
            format_str = "{0:04x}: {1:0" + str(2*fld_Salt_length) + "x} {2:2} {3:<24} {4:d}"
            print(format_str.format(i, fld_Salt_value, "", "Salt value:", fld_Salt_value))
            i += fld_Salt_length

        elif type_name == "DS":
            i_start = i

            fld_Key_id = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Key_id, "", "Key_id:", fld_Key_id))
            i += 2

            fld_Algorithm = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4}({5:d})".format(i, fld_Algorithm, "", "Algorithm:", get_algorithm(fld_Algorithm)[0], fld_Algorithm))
            i += 1

            fld_Digest_type = data[i]
            print("{0:04x}: {1:02x} {2:10} {3:<24} {4}({5:d})".format(i, fld_Digest_type, "", "Digest type:", get_digest_type(fld_Digest_type), fld_Digest_type))
            i += 1

            fld_Public_Key_size = fld_data_length - (i - i_start)
            fld_Public_Key = data[i:i + fld_Public_Key_size]
            format_str = "{0:04x}: {1:0" + str(2*fld_Public_Key_size) + "x}\n {2:18} {3:<24}"
            print(format_str.format(i, int.from_bytes(fld_Public_Key, 'big'), "", "Digest:"), end = "")
            print_result_bin(fld_Public_Key)
            i += fld_Public_Key_size

        elif type_name == "AAAA":
            print("{0:04x}: {1:02x}{2:02x}{3:02x}{4:02x}{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}{11:02x}{12:02x}{13:02x}{14:02x}{15:02x}{16:02x}\n {17:18} {18} {19}".format(i,
                data[i], data[i + 1], data[i + 2], data[i + 3],
                data[i + 4], data[i + 5], data[i + 6], data[i + 7],
                data[i + 8], data[i + 9], data[i + 10], data[i + 11],
                data[i + 12], data[i + 13], data[i + 14], data[i + 15],
                "", "Addr:", get_stripv6addr(data[i:i + 16])))
            i += fld_data_length

        elif type_name == "SRV":
            i_start = i

            fld_Priority = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Priority, "", "Priority:", fld_Priority))
            i += 2

            fld_Weight = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Weight, "", "Weight:", fld_Weight))
            i += 2

            fld_Port = (data[i] << 8) + data[i + 1]
            print("{0:04x}: {1:04x} {2:8} {3:<24} {4:d}".format(i, fld_Port, "", "Port:", fld_Port))
            i += 2

            result, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big') ,"", "Target:", result))
            i += result_length

        elif type_name == "PTR":
            result, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big') ,"", "Domain Name:", result))
            i += result_length

        elif type_name == "CAA":
            i_start = i

            print("{0:04x}: {1:04x} {2:8} {3:<24} {1:d}".format(i, data[i], "", "CAA Flags:"))
            i += 1

            result, result_length = get_name(data, i)
            format_str = "{0:04x}: {1:0" + str(2*result_length) + "x}\n {2:18} {3:<24} {4}"
            print(format_str.format(i, int.from_bytes(data[i:i + result_length], 'big') ,"", "Issue Tag:", result))
            i += result_length

            fld_issue_value = data[i:i + fld_data_length - (i - i_start)]
            format_str = "{0:04x}: {1:0" + str(2*len(fld_issue_value)) + "x} {2:12} {3}"
            print(format_str.format(i, int.from_bytes(fld_issue_value, 'big'), "Issue Value:", fld_issue_value))
            i += len(fld_issue_value)

        else:
            fld_other = data[i:i + fld_data_length]
            format_str = "{0:04x}: {1:0" + str(2*fld_data_length) + "x} {2:12} {3}"
            print(format_str.format(i, int.from_bytes(fld_other, 'big'), "Data:", fld_other))
            i += fld_data_length

        record_count += 1

    return i

def get_name(data, i):
    result = ""
    start_i = i
    while i < len(data):
        fld_length = data[i]
        if fld_length == 0:
            if result == "":
                result += "<Root>"
            i += 1
            break

        if i + 1 >= len(data):
            break

        result_bits = ((data[i] << 8) + data[i + 1]) & 0xC000
        if result_bits == 0xc000:
            result_pos = ((data[i] << 8) + data[i + 1]) & 0x3fff
            pre_name, _ = get_name(data, result_pos)
            result += "[." + pre_name + "]"
            i += 2
            break
        elif result_bits == 0x8000:
            i += 2
            break
        elif result_bits == 0x4000:
            i += 2
            break
        else:
            i += 1

        if len(result) > 0:
            result += "."

        for n in range(fld_length):
            if i + n >= len(data):
                return i + n, result
            result += chr(data[i + n])

        i += fld_length
        if i >= len(data):
            break

    return result, i - start_i


def get_signature(data, i, size):
    current_i = i
    result = ""
    max_i = i + size
    while i < max_i:
        result += chr(data[i])
        i += 1
    return result, i - current_i 


def print_result(target_str):
    col = 0
    for i in range(len(target_str)):
        if col % 16 == 0 and col >= 16:
            print("\n{0:44} {1:02x}".format("", ord(target_str[i])), end = "")
        else:
            print(" {0:02x}".format(ord(target_str[i])), end = "")
        col += 1
    print()


def print_result_bin(target_str):
    col = 0
    for i in range(len(target_str)):
        if col % 16 == 0 and col >= 16:
            print("\n{0:44} {1:02x}".format("", ord(chr(target_str[i]))), end = "")
        else:
            print(" {0:02x}".format(ord(chr(target_str[i]))), end = "")
        col += 1
    print()
