# pyDNSdump

This program sends a UDP DNS request and outputs a response.


## 1. How to execute pyDNSdump.py

```
python pyDNSdump.py [dnsserver] [target] [recordtype]
```

### Supported record types

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
