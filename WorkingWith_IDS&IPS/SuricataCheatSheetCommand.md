CHEAT SHEET SURICATA
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
- 

tips
-i								= switch otomatis untuk tinggal sebutkan saja NetInterface biarkan suricata yang memilih mesin terbaik(af-packet)
--af-packet							= switch menyedot packet langsung dari interface
--pcap								= gunakan untuk membaca file pcap
