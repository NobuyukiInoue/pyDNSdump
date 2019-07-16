#!/bin/bash

if [ $# -lt 2 ]; then
    printf "Usage) ${0} [dnsserver] [target]\n"
    exit
fi

records=("" "ANY" "SOA" "NS" "MX" "CNAME" "A" "AAAA" "TXT" "PTR" "DNSKEY" "DS" "RRSIG" "NSEC" "NSEC3PARAM" "CAA")
TARGET_PROGRAM="../pyDNSdump.py"

for record in ${records[@]}; do
    printf "Execute ... python ${TARGET_PROGRAM} ${1} ${2} ${record}\n"
    python ${TARGET_PROGRAM} ${1} ${2} ${record}
done
