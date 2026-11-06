## Struktur Suricata Rules
``` suricata
action protocol from_ip port -> to_ip port (
  msg:"Known malicious behavior, possible X malware infection";
  content:"some thing";
  content:"some other thing";
  sid:10000001; rev:1;
)
```
### Header
``` suricata
action protocol from_ip port -> to_ip port
```
### Rule Content
``` suricata
(msg:"Known malicious behavior, possible X malware infection";
content:"some thing";
content:"some other thing";
sid:10000001; rev:1;)
```
## Rule Detecting PowerShell Empire
alert ini akan terpicu LocalNet (`$HOME_NET`) melakukan request `HTTP` `GET` ke luar (`$EXTERNAL_NET`) dengan aturan:
- **Target & Halaman:** Mengakses file `.php` tertentu di root web (`login.php`, `admin.php`, `get.php`, `process.php`, `news.php`, dll).
- **Malicious Cookie:** Terdapat paramenter `session=` pada cookie yang berisikan command yang disamarkan menggunakan enkripsi Base64
- **User-Agent Palsu:** di rule ini menggunakan bawaan tools yaitu win7, User Agent ini digunakan sebagai identitas palsu untuk penyamaran, bisa saja hacker menyesuaikan mengikuti mayoritas OS terkini
- **Header Bersih:** Tidak Memiliki header standar seperti `Referer`, `Cache` maupun `Accept`.
``` suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
  msg:"ET MALWARE Possible PowerShell Empire Activity Outbound";
  flow:established,to_server;
  content:"GET"; http_method;
  content:"/"; http_uri; depth:1;
  pcre:"/^(?:login/process|admin/get|news)\.php$/RU";
  content:"session="; http_cookie;
  pcre:"/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=|[A-Z0-9+/]{4})$/CRi";
  content:"Mozilla|2f|5.0|20 28|Windows|20|NT|20|6.1"; http_user_agent; http_start;
  content:".php|20|HTTP|2f|1.1|0d 0a|Cookie|3a 20|session="; fast_pattern; http_header_names;
  content:!"Referer"; content:!"Cache"; content:!"Accept";
  sid:2027512; rev:1;
)
```
