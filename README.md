V2Ray Config Checker
Tool Python untuk memeriksa config VLESS, VMess, Trojan dari subscription URL yang masih aktif (latency < 5 detik). Output disimpan ke active_configs.txt dalam format asli (vmess://..., dll.), diurutkan berdasarkan latency tercepat.
Cara Pakai

Buka GitHub Codespaces di repo ini (tab Code > Create codespace).
Di terminal Codespaces, install dependensi:pip install requests


Jalankan:python checker.py

Masukkan subscription URL saat diminta.
Config aktif disimpan di active_configs.txt.

Contoh Output (active_configs.txt)
vmess://eyJ2IjoiMiIsInBzIjoiTest1IiwiYWR... # Latency: 150ms
vless://uuid@server.com:443?type=ws&path=/ws... # Latency: 200ms

Catatan

Gunakan sub URL legal dan milik Anda.
Tool otomatis download Xray binary saat dijalankan.
Jika sub URL butuh autentikasi, beri tahu pembuat untuk update kode.
Untuk config kompleks (misal gRPC), hubungi pembuat.
