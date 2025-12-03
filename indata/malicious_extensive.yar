rule MALWARE_SIG_A {
    strings:
        $a = "MALICIOUS_SIGNATURE"
        $b = "evil_payload_123"
    condition:
        $a or $b
}

rule Ransom_Indicator {
    strings:
        $x = ":::ENCRYPTED:::"
    condition:
        $x
}
