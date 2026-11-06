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
## Rule Detecting Covenant (By Content)
rule ini berfungsi untuk mendeteksi Tools bernama Covenant
alert ini akan terpicu jika:
- isi dari payload jika menemukan kalimat HTML `<title>Hello World!</title>`
- IP yang sama mengirim payload ini sebanyak 4x dalam 10 detik.
``` suricata
alert tcp any any -> $HOME_NET any (
  msg:"detected by body";
  content:"<title>Hello World!</title>";
  detection_filter: track by_src, count 4 , seconds 10;
  priority:1; sid:3000011;
)
```
## Rule Detecting Covenant (Using Analytic)
rule ini berfungsi untuk mendeteksi Tools bernama Covenant
bedanya dengan diatas alert ini akan terpicu jika
- ukuran data yang dikirim sebesar `dsize=312`
berdasarkan perilaku Covenant yang secara konsisten menggunakan ukuran data `312`
``` suricata
alert tcp $HOME_NET any -> any any (
  msg:"detected by size and counter";
  dsize:312;
  detection_filter: track by_src, count 3 , seconds 10;
  priority:1; sid:3000001;
)
```
## Rule Detecting Sliver
## Refference
- https://suricata.readthedocs.io/en/latest/rules/http-keywords.html
- https://docs.suricata.io/en/latest/rules/index.html.
- https://github.com/EmpireProject/Empire/blob/master/data/agent/agent.ps1#L78
- https://www.keysight.com/blogs/tech/nwvs/2021/06/16/empire-c2-networking-into-the-dark-side
- https://repositorio-aberto.up.pt/bitstream/10216/142718/2/572020.pdf
- https://github.com/cobbr/Covenant
- https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Profiles/DefaultHttpProfile.yaml#L35
- https://github.com/cobbr/Covenant/blob/master/Covenant/Data/Profiles/DefaultHttpProfile.yaml
- https://www.bilibili.com/read/cv19510951/
