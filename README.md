# pyDNSdump

This program sends a DNS UDP request and outputs a response.

## Requirements

Python 3.5 or later 

### Supported OS

* MS-Windows
* macOS
* Linux

## How to execute pyDNSdump.py

```
python pyDNSdump.py [dnsserver] [target] [recordtype]
```

## Supported record types

* ANY(255)
* A(1)
* NS(2)
* CNAME(5)
* SOA(6)
* PTR(12)
* HINFO(13)
* MX(15)
* TXT(16)
* AAAA(28)
* SRV(33)
* DS(43)
* RRSIG(46)
* DNSKEY(48)
* NSEC3(50)
* NSEC3PARAM(51)
* CAA(257)

## Demo

```
PS Z:\pyDNSdump> python .\pyDNSdump.py 172.31.0.2 . ns
============================================================================================
DNS Server    = 172.31.0.2:53
target        = .
record type   = NS
============================================================================================
Reply from    : 172.31.0.2:53
length        : 0x00e4(228) bytes.
Response time : 32.200098[ms]
============================================================================================
0000:               Header:
0000: 0001          Transaction ID:          1
0002: 8180          Flags:                   0b1000000110000000
/*
                      [bit 0]     QR      (1) ... Response
                      [bit 1-4]   OPCODE  (0) ... standard query
                      [bit 5]     AA      (0) ... Not Authoritative
                      [bit 6]     TC      (0) ... Did not Flagment
                      [bit 7]     RD      (1) ... Repeat Query
                      [bit 8]     RA      (1) ... Recursion Available is False
                      [bit 9]     Reserve (0)
                      [bit 10]    Authentic Data(0)
                      [bit 11]    Checking Disable(0)
                      [bit 12-15] RCODE   (0) ... No Error
*/
0004: 0001          Questions:               1
0006: 000d          Answer RRS:              13
0008: 0000          Authority RRS:           0
000a: 0000          Additional RRS:          0

000c:               Querys:
000c: 00            Name:                    <Root>
000d: 0002          Type:                    NS(2)
000f: 0001          Class:                   IN(1)

0011:               Answer[0]:
0011: 00            Name:                    <Root>
0012: 0002          Type:                    NS(2)
0014: 0001          Class:                   IN(1)
0016: 0002d970      Time to live:            2 day 03:52:16(186736)
001a: 0014          data_length:             20
001c: 01620c726f6f742d73657276657273036e657400  Name:                    b.root-servers.net

0030:               Answer[1]:
0030: 00            Name:                    <Root>
0031: 0002          Type:                    NS(2)
0033: 0001          Class:                   IN(1)
0035: 0002d970      Time to live:            2 day 03:52:16(186736)
0039: 0004          data_length:             4
003b: 0163c01e      Name:                    c[.root-servers.net]

003f:               Answer[2]:
003f: 00            Name:                    <Root>
0040: 0002          Type:                    NS(2)
0042: 0001          Class:                   IN(1)
0044: 0002d970      Time to live:            2 day 03:52:16(186736)
0048: 0004          data_length:             4
004a: 016ac01e      Name:                    j[.root-servers.net]

004e:               Answer[3]:
004e: 00            Name:                    <Root>
004f: 0002          Type:                    NS(2)
0051: 0001          Class:                   IN(1)
0053: 0002d970      Time to live:            2 day 03:52:16(186736)
0057: 0004          data_length:             4
0059: 0168c01e      Name:                    h[.root-servers.net]

005d:               Answer[4]:
005d: 00            Name:                    <Root>
005e: 0002          Type:                    NS(2)
0060: 0001          Class:                   IN(1)
0062: 0002d970      Time to live:            2 day 03:52:16(186736)
0066: 0004          data_length:             4
0068: 0169c01e      Name:                    i[.root-servers.net]

006c:               Answer[5]:
006c: 00            Name:                    <Root>
006d: 0002          Type:                    NS(2)
006f: 0001          Class:                   IN(1)
0071: 0002d970      Time to live:            2 day 03:52:16(186736)
0075: 0004          data_length:             4
0077: 0166c01e      Name:                    f[.root-servers.net]

007b:               Answer[6]:
007b: 00            Name:                    <Root>
007c: 0002          Type:                    NS(2)
007e: 0001          Class:                   IN(1)
0080: 0002d970      Time to live:            2 day 03:52:16(186736)
0084: 0004          data_length:             4
0086: 016dc01e      Name:                    m[.root-servers.net]

008a:               Answer[7]:
008a: 00            Name:                    <Root>
008b: 0002          Type:                    NS(2)
008d: 0001          Class:                   IN(1)
008f: 0002d970      Time to live:            2 day 03:52:16(186736)
0093: 0004          data_length:             4
0095: 016bc01e      Name:                    k[.root-servers.net]

0099:               Answer[8]:
0099: 00            Name:                    <Root>
009a: 0002          Type:                    NS(2)
009c: 0001          Class:                   IN(1)
009e: 0002d970      Time to live:            2 day 03:52:16(186736)
00a2: 0004          data_length:             4
00a4: 0167c01e      Name:                    g[.root-servers.net]

00a8:               Answer[9]:
00a8: 00            Name:                    <Root>
00a9: 0002          Type:                    NS(2)
00ab: 0001          Class:                   IN(1)
00ad: 0002d970      Time to live:            2 day 03:52:16(186736)
00b1: 0004          data_length:             4
00b3: 0164c01e      Name:                    d[.root-servers.net]

00b7:               Answer[10]:
00b7: 00            Name:                    <Root>
00b8: 0002          Type:                    NS(2)
00ba: 0001          Class:                   IN(1)
00bc: 0002d970      Time to live:            2 day 03:52:16(186736)
00c0: 0004          data_length:             4
00c2: 016cc01e      Name:                    l[.root-servers.net]

00c6:               Answer[11]:
00c6: 00            Name:                    <Root>
00c7: 0002          Type:                    NS(2)
00c9: 0001          Class:                   IN(1)
00cb: 0002d970      Time to live:            2 day 03:52:16(186736)
00cf: 0004          data_length:             4
00d1: 0161c01e      Name:                    a[.root-servers.net]

00d5:               Answer[12]:
00d5: 00            Name:                    <Root>
00d6: 0002          Type:                    NS(2)
00d8: 0001          Class:                   IN(1)
00da: 0002d970      Time to live:            2 day 03:52:16(186736)
00de: 0004          data_length:             4
00e0: 0165c01e      Name:                    e[.root-servers.net]
============================================================================================
Reception is complete.

PS Z:\pyDNSdump>
```

## Execution examples

### 1-1. request ANY Record

```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com
```
or
```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com any
```
or
```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com 255
```

### 1-2. request A Record

```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com a
```
or
```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com 1
```

### 1-3. request CNAME Record

```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com cname
```
or
```
python pyDNSdump.py 192.168.1.1 www.hackerzlab.com 5
```

### 1-4. request NS Record

```
python pyDNSdump.py 192.168.1.1 hackerzlab.com ns
```
or
```
python pyDNSdump.py 192.168.1.1 hackerzlab.com 2
```

### 1-5. request MX Record

```
python pyDNSdump.py 192.168.1.1 hackerzlab.com mx
```
or
```
python pyDNSdump.py 192.168.1.1 hackerzlab.com 15
```

### 1-6. request SOA Record

```
python pyDNSdump.py 192.168.1.1 hackerzlab.com soa
```
or
```
python pyDNSdump.py 192.168.1.1 hackerzlab.com 6
```

### 1-7. request PTR Record

```
python pyDNSdump.py 192.168.1.1 8.8.8.8 ptr
```
or
```
python pyDNSdump.py 192.168.1.1 8.8.8.8 12
```

### 1-8. request CAA Record

```
python pyDNSdump.py 192.168.1.1 hackerzlab.com caa
```
or
```
python pyDNSdump.py 192.168.1.1 hackerzlab.com 257
```

### 1-9. request SRV Record

```
python pyDNSdump.py 192.168.1.1 _http._tcp.hackerzlab.com srv
```
or
```
python pyDNSdump.py 192.168.1.1 _http._tcp.hackerzlab.com 33
```
