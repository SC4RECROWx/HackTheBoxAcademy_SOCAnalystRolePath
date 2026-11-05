## Struktur Suricata Rules
``` suricata
action protocol from_ip port -> to_ip port (msg:"Known malicious behavior, possible X malware infection"; content:"some thing"; content:"some other thing"; sid:10000001; rev:1;)
```
Penjelasan:
### Header
``` suricata
action protocol from_ip port -> to_ip port
```
### Rule Content
``` suricata
(msg:"Known malicious behavior, possible X malware infection"; content:"some thing"; content:"some other thing"; sid:10000001; rev:1;)
```
