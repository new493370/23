import os
import re
import json
import socket
import hashlib
import ipaddress
import tempfile
import subprocess
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import base64
import time

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class DNSTimeoutError(Exception):
    pass


class IPAPIClient:
    def __init__(self):
        self.cache = {}
        self.cache_file = "configs/country/ipapi_cache.json"
        self.load_cache()

    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
        except:
            self.cache = {}

    def save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except:
            pass

    def get_country(self, ip):
        if ip in self.cache:
            cache_time = datetime.fromisoformat(self.cache[ip]['timestamp'])
            if datetime.now() - cache_time < timedelta(days=30):
                return self.cache[ip]['country']

        try:
            import urllib.request
            url = f"http://ip-api.com/json/{ip}?fields=status,countryCode"
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                if data.get('status') == 'success':
                    country = data.get('countryCode', 'XX')
                    self.cache[ip] = {
                        'country': country,
                        'timestamp': datetime.now().isoformat()
                    }
                    return country
        except:
            pass

        try:
            import urllib.request
            url = f"https://ipapi.co/{ip}/country/"
            with urllib.request.urlopen(url, timeout=5) as response:
                country = response.read().decode().strip()
                if country and len(country) == 2:
                    self.cache[ip] = {
                        'country': country,
                        'timestamp': datetime.now().isoformat()
                    }
                    return country
        except:
            pass

        return None


class RealServerDetector:
    CDN_KEYWORDS = [
        'cloudflare', 'akamai', 'fastly', 'cloudfront',
        'edgecast', 'imperva', 'cdn', 'azure', 'google'
    ]

    def __init__(self, classifier):
        self.classifier = classifier

    def get_real_server_ip(self, parsed):

        if 'real_ip' in parsed:
            ip = parsed['real_ip']
            if self.classifier.is_valid_ip(ip):
                return ip

        if parsed.get('type') == 'vmess':
            cfg = parsed.get('dict', {})
            ip = cfg.get('add', '').strip()
            if self.classifier.is_valid_ip(ip):
                return ip

        host = parsed.get('host', '').strip()
        if host:
            ips = self.classifier.resolve_domain(host)
            for ip in ips:
                if not self.is_cdn_ip(ip):
                    return ip

        return None

    def is_cdn_ip(self, ip):
        asn = self.classifier.get_asn(ip)
        if not asn:
            return False
        asn = asn.lower()
        return any(cdn in asn for cdn in self.CDN_KEYWORDS)


class CountryClassifier:
    def __init__(self):
        self.geoip_path = "geoip/GeoLite2-Country.mmdb"
        self.geoip_reader = None
        self.dns_cache = {}
        self.country_cache = {}
        self.ip_country_cache = {}
        self.cache_file = "configs/country/dns_cache.json"
        self.ipapi_client = IPAPIClient()

        self.load_cache()
        self.init_geoip()

        self.real_detector = RealServerDetector(self)

    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    for key, data in cache_data.items():
                        timestamp = datetime.fromisoformat(data['timestamp'])
                        if datetime.now() - timestamp < timedelta(days=7):
                            if key.startswith('ip_'):
                                self.ip_country_cache[key[3:]] = data['country']
                            else:
                                self.dns_cache[key] = data.get('ips', [])
        except:
            pass

    def save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            cache_data = {}
            for domain, ips in self.dns_cache.items():
                cache_data[domain] = {
                    'ips': ips,
                    'timestamp': datetime.now().isoformat()
                }
            for ip, country in self.ip_country_cache.items():
                cache_data[f'ip_{ip}'] = {
                    'country': country,
                    'timestamp': datetime.now().isoformat()
                }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            self.ipapi_client.save_cache()
        except:
            pass

    def init_geoip(self):
        if not GEOIP_AVAILABLE:
            return
        try:
            if os.path.exists(self.geoip_path):
                self.geoip_reader = geoip2.database.Reader(self.geoip_path)
        except:
            self.geoip_reader = None

    def update_geoip_database(self):
        try:
            import urllib.request
            url = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
            os.makedirs('geoip', exist_ok=True)
            urllib.request.urlretrieve(url, self.geoip_path)
            return True
        except:
            return False

    def get_asn(self, ip):
        try:
            import urllib.request
            url = f"https://ipinfo.io/{ip}/json"
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return data.get("org", "")
        except:
            return ""

    def is_valid_ip(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except:
            return False

    def resolve_domain(self, domain):
        if self.is_valid_ip(domain):
            return [domain]

        if domain in self.dns_cache:
            return self.dns_cache[domain]

        ips = []
        try:
            for family in [socket.AF_INET, socket.AF_INET6]:
                try:
                    addrinfo = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                    for addr in addrinfo:
                        ip = addr[4][0]
                        if ip not in ips:
                            ips.append(ip)
                except:
                    continue
            self.dns_cache[domain] = ips[:5]
            return ips[:5]
        except:
            return []

    def get_country_from_ip(self, ip):
        if ip in self.ip_country_cache:
            return self.ip_country_cache[ip]

        if self.geoip_reader:
            try:
                resp = self.geoip_reader.country(ip)
                if resp.country.iso_code:
                    self.ip_country_cache[ip] = resp.country.iso_code
                    return resp.country.iso_code
            except:
                pass

        ipapi_country = self.ipapi_client.get_country(ip)
        if ipapi_country:
            self.ip_country_cache[ip] = ipapi_country
            return ipapi_country

        return 'XX'

    def parse_vmess_config(self, config_str):
        try:
            if not config_str.startswith('vmess://'):
                return None

            raw = config_str[8:]
            if len(raw) % 4:
                raw += '=' * (4 - len(raw) % 4)

            decoded = base64.b64decode(raw).decode('utf-8')
            cfg = json.loads(decoded)

            return {
                'type': 'vmess',
                'host': cfg.get('host', ''),
                'real_ip': cfg.get('add', ''),
                'port': cfg.get('port', ''),
                'dict': cfg,
                'original': config_str
            }
        except:
            return None

    def parse_vless_config(self, config_str):
        try:
            without_proto = config_str[8:]
            uuid, rest = without_proto.split('@', 1)
            server_part = rest.split('?', 1)[0].split('#')[0]

            if ':' in server_part:
                real_ip, port = server_part.split(':', 1)
            else:
                real_ip, port = server_part, '443'

            params = {}
            if '?' in rest:
                params = parse_qs(rest.split('?', 1)[1].split('#')[0])

            return {
                'type': 'vless',
                'host': params.get('host', [''])[0],
                'real_ip': real_ip.strip(),
                'port': port.strip(),
                'original': config_str
            }
        except:
            return None

    def parse_trojan_config(self, config_str):
        try:
            without_proto = config_str[9:]
            passwd, rest = without_proto.split('@', 1)
            server_part = rest.split('?', 1)[0].split('#')[0]

            if ':' in server_part:
                real_ip, port = server_part.split(':', 1)
            else:
                real_ip, port = server_part, '443'

            params = {}
            if '?' in rest:
                params = parse_qs(rest.split('?', 1)[1].split('#')[0])

            return {
                'type': 'trojan',
                'host': params.get('host', [''])[0],
                'real_ip': real_ip.strip(),
                'port': port.strip(),
                'original': config_str
            }
        except:
            return None

    def parse_ss_config(self, config_str):
        try:
            if not config_str.startswith('ss://'):
                return None

            raw = config_str[5:]
            if '@' in raw:
                part, rest = raw.split('@', 1)
                host_port = rest.split('#')[0]
                host, port = host_port.split(':', 1)
            else:
                raw += '=' * (4 - len(raw) % 4)
                decoded = base64.b64decode(raw).decode()
                method_pass, host_port = decoded.split('@', 1)
                host, port = host_port.split(':', 1)

            return {
                'type': 'ss',
                'host': '',
                'real_ip': host.strip(),
                'port': port.strip(),
                'original': config_str
            }
        except:
            return None

    def parse_config(self, config_str):
        if config_str.startswith('vmess://'):
            return self.parse_vmess_config(config_str)
        elif config_str.startswith('vless://'):
            return self.parse_vless_config(config_str)
        elif config_str.startswith('trojan://'):
            return self.parse_trojan_config(config_str)
        elif config_str.startswith('ss://'):
            return self.parse_ss_config(config_str)
        return None

    def classify_config(self, config):
        parsed = self.parse_config(config)
        if not parsed:
            return None, 'XX'

        ip = self.real_detector.get_real_server_ip(parsed)
        if not ip:
            return None, 'XX'

        return parsed, self.get_country_from_ip(ip)

    def process_file(self, input_file):
        results = {}
        failed = 0

        with open(input_file, 'r', encoding='utf-8') as f:
            configs = [line.strip() for line in f if line.strip()]

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.classify_config, c): c for c in configs}

            for future in as_completed(futures):
                try:
                    parsed, country = future.result(timeout=10)
                    if parsed and country != 'XX':
                        results.setdefault(country, []).append(parsed['original'])
                    else:
                        failed += 1
                except:
                    failed += 1

        return results, len(configs), failed


def main():
    print("=" * 60)
    print("🌍 ARISTA ENTERPRISE COUNTRY CLASSIFIER")
    print("=" * 60)

    classifier = CountryClassifier()

    print("\n📥 Updating GeoIP database...")
    if classifier.update_geoip_database():
        print("✅ GeoIP updated")

    input_file = "configs/combined/all.txt"
    if not os.path.exists(input_file):
        print("❌ configs/combined/all.txt not found")
        return

    results, total, failed = classifier.process_file(input_file)

    os.makedirs("configs/country", exist_ok=True)

    for country, configs in results.items():
        path = f"configs/country/{country}"
        os.makedirs(path, exist_ok=True)

        with open(f"{path}/all.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(configs))

    print("\n📊 RESULTS")
    print(f"Total: {total}")
    print(f"Valid: {sum(len(v) for v in results.values())}")
    print(f"Failed: {failed}")
    print(f"Countries: {len(results)}")

    classifier.save_cache()

    print("\n" + "=" * 60)
    print("✅ ENTERPRISE CLASSIFICATION COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
