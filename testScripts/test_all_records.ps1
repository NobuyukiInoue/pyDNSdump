param($dns_server, $target)

if (-Not($dns_server) -Or -Not($target)) {
    Write-Host "Usage) "$MyInvocation.MyCommand.Name" [dnsserver] [target]"
    exit
}

$records = @("", "ANY", "SOA", "NS", "MX", "CNAME", "A", "AAAA", "TXT", "PTR", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3PARAM", "CAA")
$target_program = "../pyDNSdump.py"

foreach($record in $records) {
    Write-Host "Eecute ... python ${target_program} ${dns_server} ${target} ${record}"
    python ${target_program} ${dns_server} ${target} ${record}
}
