# CHEAT SHEET SURICATA
``` bash
- /etc/suricata/rules						= isi Suricata Rules
- /etc/suricata/suricata.yaml					= konfigurasi Suricata
- suricata -r <File .pcap>					= Membaca file pcaps
- suricata -k none -l .						= <-k none> wajib hindari checksum untuk read offline dan <-l <folder>> untuk menyimpan record
- suricata --pcap=<net interface -vv>				= membaca jaringan yang ada di net interface (live record) & -vv menampilkan data di cli (verbose)
- iptables -I FORWARD -J NFQUEUE				= menahan paket dan memasukkan ke antrian
- suricata -q 0 						= memeriksa antrian dan akan ditentukan apakah ACCEPT/DROP (IPS MODE) jalankan command iptables diatas untuk memulai command ini
- suricata -i <net interface>					= memantau network interface (mengaktifkan IDS)
- suricata --af-packet						= memantau network interface (mengaktifkan IDS)
- tcpreplay -i <net interface> <file pcap>			= mengulang rekaman Network Traffic ke Net interface secara Live solah olah kejadiannya terjadi saat ini
- /var/log/suricata						= log NetworkTraffic yang telah diamati
- cat <json file> | jq -c 'select(.event_type=="<event type>")'	= memfilter event type tertentu TLS,SSH,DNS,ALERT DLL
- cat <json file> | jq -c 'select(.event_type=="alert")'	= filter untuk melihat hanya alert event
- cat <json file> | jq -c 'select(.event_type=="dns")'		= filter untuh melihat hanya alert DNS dan hanya mengambil baris DNS paling awal (head -1)
		  | head -1 | jq .
- | jq .							= untuk merapikan output json
- .pcap_cnt							= untuk melihat nomor antrian paket
- .flow.id							= untuk melihat ID paket
- cat <json file> | jq -c 'select(.event_type=="<event type>")	= contoh untuk melihat nomor antrian
		  | .pcap_cnt
- find . -type f						= memfilter hanya untuk mencari file saja type yang lain seperti dir akan di abaikan
sudo kill -usr2 $(pidof suricata)				= command untuk merefresh/update rules suricata secara realtime tanpa mematikan suricata
```

## tips
``` bash
- -i								= switch otomatis untuk tinggal sebutkan saja NetInterface biarkan suricata yang memilih mesin terbaik(af-packet)
- --af-packet							= switch menyedot packet langsung dari interface
- --pcap							= gunakan untuk membaca file pcap
- fast.log							= hanya menampilkan Alert
- eve.log							= menampilkan semua event
- stats.log							= menampilkan kinerja mesin/suricata (memantau performa suricata)
- suricata.log							= menampilkan log suricata
- filestore							= tempat suricata menyimpan file hasil ekstraksi
- find . -type f						= mencari type file saja (biasanya digunakan pada filestore)
- xxd <file filestore> | head					= membongkar file filestore yang berhasil di ekstrak dan mengambil bagian atasnya saja (head)
- sudo kill -usr2 $(pidof suricata)				= command untuk mengupdate rule suricata tanpa mematikannya
- sudo suricata-update						= untuk mengupdate suricata dari sumber terpercaya di internet
- sudo suricata-update list-sources				= untuk menampilkan daftar source terpercaya di internet yang terpasang di suricata
- sudo suricata-update enable-source <RuleName>			= untuk mengaktifkan dan memilih salah satu rules yang ada di list-sources
- sudo systemctl restart suricata				= untuk merestart suricata
- sudo suricata -T -c /etc/suricata/suricata.yaml		= command untuk mengecek konfigurasi apakah sudah benar atau ada salah tulis yang dapat menciptakan error
```


## scripting / rules
``` yaml
#untuk mengaktifkan filestore (di folder /etc/suricata/suricata.yaml)
file-store:
	version: 2
	enabled: yes
	force-filestore: yes
  ```

``` yaml
# rule untuk menyimpan semua file HTTP ke filestore
alert http any any -> any any (msg:"FILE store all";filestore; sid:2;rev:1;)
```

``` yaml
# rule izin update rule realtime (tanpa mematikan suricata, lokasi: /etc/suricata/suricata.yaml)
detect-engine:
  - reload: true
```

## Refference
https://www.netresec.com/?page=PcapFiles <br>
https://docs.suricata.io/en/suricata-8.0.8/ <br>
https://redmine.openinfosecfoundation.org/search?scope=&q=rules

## Fitur Utama Suricata
### Fitur-fitur utama yang meningkatkan efektivitas Suricata meliputi:

- Inspeksi paket mendalam dan pencatatan tangkapan paket.
- Deteksi Anomali dan Pemantauan Keamanan Jaringan
- Deteksi dan Pencegahan Intrusi, dengan mode hibrida yang tersedia.
- Pemrograman Lua
- Identifikasi IP geografis (GeoIP)
- Dukungan penuh untuk IPv4 dan IPv6
- Reputasi IP
- Ekstraksi file
- Inspeksi protokol lanjutan
- Multitenancy
