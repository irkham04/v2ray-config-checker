import json
import base64
import urllib.parse
import subprocess
import tempfile
import os
import time
import requests
import zipfile
import stat

# Path ke Xray binary (akan dibuat otomatis)
XRAY_PATH = "./bin/xray"
XRAY_URL = "https://github.com/XTLS/Xray-core/releases/download/v1.8.23/Xray-linux-64.zip"  # Ganti versi jika perlu

# Port lokal untuk proxy test
LOCAL_PORT = 1080

# URL untuk test koneksi
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 10  # Detik
MAX_LATENCY = 5000  # ms (config aktif kalau latency < 5 detik)

def setup_xray():
    """Download dan setup Xray binary jika belum ada"""
    if os.path.exists(XRAY_PATH):
        return True
    try:
        print("Downloading Xray binary...")
        os.makedirs("bin", exist_ok=True)
        zip_path = "bin/xray.zip"
        response = requests.get(XRAY_URL, stream=True)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extract("xray", "bin")
        os.remove(zip_path)
        os.chmod(XRAY_PATH, stat.S_IXUSR | stat.S_IRUSR | stat.S_IWUSR)  # Buat executable
        print("Xray binary ready!")
        return True
    except Exception as e:
        print(f"Gagal setup Xray: {e}")
        return False

def fetch_sub_url(sub_url):
    """Ambil config dari subscription URL"""
    try:
        response = requests.get(sub_url, timeout=10)
        response.raise_for_status()
        content = response.text
        try:
            content = base64.b64decode(content).decode('utf-8')
        except:
            pass
        return [line.strip() for line in content.splitlines() if line.strip()]
    except Exception as e:
        print(f"Gagal ambil sub URL: {e}")
        return []

def parse_config(config_str):
    """Parse config VMess/VLESS/Trojan ke dict"""
    if config_str.startswith('vmess://'):
        try:
            payload = base64.b64decode(config_str[8:]).decode('utf-8')
            return json.loads(payload), 'vmess'
        except:
            return None, None
    elif config_str.startswith('vless://'):
        try:
            parsed = urllib.parse.urlparse(config_str)
            query = urllib.parse.parse_qs(parsed.query)
            return {
                'ps': parsed.fragment or 'vless',
                'add': parsed.hostname,
                'port': parsed.port,
                'id': parsed.username,
                'net': parsed.scheme.split('+')[1] if '+' in parsed.scheme else 'tcp',
                'path': query.get('path', ['/'])[0],
                'tls': 'tls' if query.get('security', [''])[0].lower() == 'tls' else 'none',
                'sni': query.get('sni', [parsed.hostname])[0]
            }, 'vless'
        except:
            return None, None
    elif config_str.startswith('trojan://'):
        try:
            parsed = urllib.parse.urlparse(config_str)
            query = urllib.parse.parse_qs(parsed.query)
            return {
                'ps': parsed.fragment or 'trojan',
                'add': parsed.hostname,
                'port': parsed.port,
                'password': parsed.username,
                'net': query.get('type', ['tcp'])[0],
                'path': query.get('path', ['/'])[0],
                'sni': query.get('sni', [parsed.hostname])[0],
                'security': 'tls'
            }, 'trojan'
        except:
            return None, None
    return None, None

def generate_xray_config(parsed_config, protocol):
    """Buat config JSON untuk Xray"""
    if protocol == 'vmess':
        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": LOCAL_PORT, "protocol": "socks", "listen": "127.0.0.1", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vmess",
                "settings": {"vnext": [{"address": parsed_config['add'], "port": int(parsed_config['port']), "users": [{"id": parsed_config['id'], "alterId": int(parsed_config.get('aid', 0)), "security": parsed_config.get('scy', 'auto')}]}]},
                "streamSettings": {
                    "network": parsed_config.get('net', 'tcp'),
                    "security": parsed_config.get('tls', 'none'),
                    "wsSettings": {"path": parsed_config.get('path', '/'), "headers": {"Host": parsed_config.get('host', '')}} if parsed_config.get('net') == 'ws' else None
                }
            }]
        }
    elif protocol == 'vless':
        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": LOCAL_PORT, "protocol": "socks", "listen": "127.0.0.1", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "vless",
                "settings": {"vnext": [{"address": parsed_config['add'], "port": int(parsed_config['port']), "users": [{"id": parsed_config['id'], "encryption": "none"}]}]},
                "streamSettings": {
                    "network": parsed_config['net'],
                    "security": parsed_config['tls'],
                    "wsSettings": {"path": parsed_config['path'], "headers": {"Host": parsed_config['host']}} if parsed_config['net'] == 'ws' else None
                }
            }]
        }
    elif protocol == 'trojan':
        return {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": LOCAL_PORT, "protocol": "socks", "listen": "127.0.0.1", "settings": {"udp": True}}],
            "outbounds": [{
                "protocol": "trojan",
                "settings": {"servers": [{"address": parsed_config['add'], "port": int(parsed_config['port']), "password": parsed_config['password']}]},
                "streamSettings": {"network": parsed_config['net'], "security": "tls", "tlsSettings": {"serverName": parsed_config['sni']}}
            }]
        }
    return None

def test_config(config_str):
    """Test config: parse, jalankan Xray, cek latency"""
    parsed, protocol = parse_config(config_str)
    if not parsed or not protocol:
        return False, "Parse gagal", None
    
    config_json = generate_xray_config(parsed, protocol)
    if not config_json:
        return False, "Generate config gagal", None
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_json, f, indent=2)
        temp_config = f.name
    
    try:
        proc = subprocess.Popen([XRAY_PATH, 'run', '-c', temp_config], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)
        start_time = time.time()
        proxies = {'http': f'socks5://127.0.0.1:{LOCAL_PORT}', 'https': f'socks5://127.0.0.1:{LOCAL_PORT}'}
        response = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
        latency = int((time.time() - start_time) * 1000)
        
        if response.status_code == 200 and latency < MAX_LATENCY:
            proc.terminate()
            os.unlink(temp_config)
            return True, f"Aktif, latency: {latency}ms", latency
        else:
            proc.terminate()
            os.unlink(temp_config)
            return False, f"Gagal connect atau latency tinggi: {latency}ms", latency
    except Exception as e:
        if 'proc' in locals():
            proc.terminate()
        if os.path.exists(temp_config):
            os.unlink(temp_config)
        return False, f"Error: {e}", None

def main():
    # Setup Xray binary
    if not setup_xray():
        print("Gagal setup Xray, keluar...")
        return
    
    sub_url = input("Masukkan subscription URL: ").strip()
    configs = fetch_sub_url(sub_url)
    
    if not configs:
        print("Tidak ada config dari sub URL!")
        return
    
    active_configs = []
    print(f"Testing {len(configs)} configs...")
    
    for i, config in enumerate(configs, 1):
        print(f"[{i}/{len(configs)}] Testing: {config[:50]}...")
        is_active, msg, latency = test_config(config)
        if is_active:
            active_configs.append((config, latency))
            print(f"  ✓ {msg}")
        else:
            print(f"  ✗ {msg}")
    
    # Urutkan berdasarkan latency (tercepat dulu)
    active_configs.sort(key=lambda x: x[1] if x[1] is not None else float('inf'))
    
    # Simpan ke file dalam format asli
    output_file = "active_configs.txt"
    with open(output_file, 'w') as f:
        for config, latency in active_configs:
            f.write(f"{config} # Latency: {latency}ms\n")
    
    print(f"\nSelesai! {len(active_configs)} config aktif disimpan di {output_file}")

if __name__ == "__main__":
    main()
