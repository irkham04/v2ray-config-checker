import json
import base64
import urllib.parse
import subprocess
import tempfile
import os
import time
import requests

# Path ke Xray binary (sesuaikan nanti di Codespaces atau lokal)
XRAY_PATH = "./bin/xray"  # atau "./bin/xray.exe" di Windows

# Port lokal untuk proxy test
LOCAL_PORT = 1080

# URL untuk test koneksi
TEST_URL = "http://httpbin.org/ip"
TIMEOUT = 10  # Detik
MAX_LATENCY = 5000  # ms (config aktif kalau latency < 5 detik)

def fetch_sub_url(sub_url):
    """Ambil config dari subscription URL"""
    try:
        response = requests.get(sub_url, timeout=10)
        response.raise_for_status()
        content = response.text
        try:
            content = base64.b64decode(content).decode('utf-8')  # Decode kalau base64
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
            "inbounds": [{"port": LOCAL_PORT, "protocol": "socks", "listen": "127.0.0.1", "settings": {"udp
