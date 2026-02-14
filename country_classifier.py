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
            import json
            
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

class TrustScorer:
    def __init__(self, classifier):
        self.classifier = classifier

    def extract_host_value(self, original):
        try:
            match = re.search(r'host=([^&]+)', original)
            if match:
                return match.group(1)
        except:
            return None
        return None

    def score(self, parsed):
        score = 0
        t = parsed.get('type', '')
        host = parsed.get('host', '')
        original = parsed.get('original', '')
        
        if self.classifier.is_valid_ip(host):
            score += 3
        
        if t in ['vless', 'trojan', 'ss']:
            score += 1
        
        if t == 'vmess':
            net = parsed.get('dict', {}).get('net', '')
            if net == 'tcp':
                score += 2
        
        if 'type=ws' in original or 'type=grpc' in original:
            score -= 4
        
        if 'host=' in original:
            host_value = self.extract_host_value(original)
            if host_value and not self.classifier.is_valid_ip(host_value):
                score -= 3
        
        for cdn in self.classifier.cdn_domains:
            if cdn in original:
                return 0
        
        if 'reality' in original:
            score += 3
        
        if 'security=tls' in original:
            score += 4
        elif 'security=none' in original:
            score -= 3
        
        if 'path=' in original:
            score -= 2
        
        if 'encryption=none' in original:
            score -= 1
        
        return score

class RealServerDetector:
    def __init__(self, classifier):
        self.classifier = classifier
        self.trust = TrustScorer(classifier)

    def get_real_server_ip(self, parsed):
        proto = parsed.get('type', '')

        if proto == 'vmess':
            cfg = parsed.get('dict', {})
            ip = cfg.get('add', '').strip()
            if self.classifier.is_valid_ip(ip):
                return ip
            return None

        ip = parsed.get('host', '').strip()

        if self.classifier.is_valid_ip(ip):
            return ip

        return None

    def get_real_country(self, parsed):
        score = self.trust.score(parsed)
        
        if score < 7:
            return 'XX'
        
        ip = self.get_real_server_ip(parsed)
        
        if not ip:
            return 'XX'
        
        return self.classifier.get_country_from_ip(ip)

class CountryClassifier:
    def __init__(self):
        self.geoip_path = "geoip/GeoLite2-Country.mmdb"
        self.geoip_reader = None
        self.cdn_domains = self.load_cdn_domains()
        self.dns_cache = {}
        self.country_cache = {}
        self.ip_country_cache = {}
        self.cache_file = "configs/country/dns_cache.json"
        self.ipapi_client = IPAPIClient()
        self.load_cache()
        self.init_geoip()
        self.real_detector = RealServerDetector(self)
        
    def load_cdn_domains(self):
        return {
            'cloudflare.com', 'cloudflare.net', 'cloudflarecdn.com',
            'cloudfront.net', 'aws.amazon.com', 'amazonaws.com',
            'akamai.net', 'akamaiedge.net', 'akamaitechnologies.com',
            'fastly.net', 'fastly.com', 'edgecastcdn.net',
            'azureedge.net', 'azure.com', 'windows.net',
            'googleapis.com', 'gstatic.com', 'googleusercontent.com',
            'cdn77.org', 'cdn77.com', 'stackpathdns.com',
            'hscdn.net', 'cdngateway.net', 'kinxcdn.com',
            'bitgravity.com', 'incapdns.net', 'impervadns.net',
            'nocookie.net', 'tastatic.com', 'v2ex.co',
            'github.io', 'github.com', 'raw.githubusercontent.com',
            'jsdelivr.net', 'cdn.jsdelivr.net', 'unpkg.com',
            'bootstrapcdn.com', 'cloudflare-ipfs.com',
            'apple.com', 'apple-dns.net', 'itunes.apple.com'
        }
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    for key, data in cache_data.items():
                        try:
                            timestamp = datetime.fromisoformat(data['timestamp'])
                            if datetime.now() - timestamp < timedelta(days=7):
                                if key.startswith('ip_'):
                                    ip = key[3:]
                                    self.ip_country_cache[ip] = data['country']
                                else:
                                    self.dns_cache[key] = data.get('ips', [])
                                    if 'country' in data:
                                        self.country_cache[key] = data['country']
                        except:
                            continue
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
                if domain in self.country_cache:
                    cache_data[domain]['country'] = self.country_cache[domain]
            
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
            else:
                alt_paths = [
                    "GeoLite2-Country.mmdb",
                    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
                    "/var/lib/GeoIP/GeoLite2-Country.mmdb"
                ]
                for path in alt_paths:
                    if os.path.exists(path):
                        self.geoip_reader = geoip2.database.Reader(path)
                        break
        except:
            self.geoip_reader = None
    
    def is_valid_ip(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except:
            return False
    
    def is_cdn_domain(self, domain):
        domain_lower = domain.lower()
        for cdn in self.cdn_domains:
            if cdn in domain_lower or domain_lower.endswith('.' + cdn):
                return True
        return False
    
    def extract_domain(self, host):
        if self.is_valid_ip(host):
            return host
        
        try:
            parsed = urlparse(host)
            if parsed.hostname:
                return parsed.hostname.lower()
            
            if ':' in host and not host.startswith('http'):
                host_part = host.split(':')[0]
                if '.' in host_part:
                    return host_part.lower()
            
            return host.lower()
        except:
            return host.lower()
    
    def resolve_domain(self, domain):
        if self.is_valid_ip(domain):
            return [domain]
        
        if domain in self.dns_cache:
            return self.dns_cache[domain]
        
        try:
            ips = []
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
            self.dns_cache[domain] = []
            return []
    
    def get_country_from_ip(self, ip):
        if ip in self.ip_country_cache:
            return self.ip_country_cache[ip]
        
        if self.geoip_reader:
            try:
                response = self.geoip_reader.country(ip)
                if response.country.iso_code:
                    country = response.country.iso_code
                    self.ip_country_cache[ip] = country
                    return country
            except:
                pass
        
        ipapi_country = self.ipapi_client.get_country(ip)
        if ipapi_country:
            self.ip_country_cache[ip] = ipapi_country
            return ipapi_country
        
        self.ip_country_cache[ip] = 'XX'
        return 'XX'
    
    def get_country_for_host(self, host):
        host = self.extract_domain(host)

        if self.is_valid_ip(host):
            return self.get_country_from_ip(host)

        ips = self.resolve_domain(host)
        if ips:
            return self.get_country_from_ip(ips[0])

        return 'XX'
    
    def parse_vmess_config(self, config_str):
        try:
            if not config_str.startswith('vmess://'):
                return None
            
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            
            import base64
            import json
            decoded = base64.b64decode(base64_part).decode('utf-8')
            config_dict = json.loads(decoded)
            
            if 'ps' not in config_dict:
                config_dict['ps'] = 'ARISTA🔥'
            
            host = config_dict.get('add', '')
            port = config_dict.get('port', '')
            
            return {
                'type': 'vmess',
                'host': host,
                'port': port,
                'original': config_str,
                'dict': config_dict
            }
        except Exception as e:
            return None
    
    def parse_vless_config(self, config_str):
        try:
            if not config_str.startswith('vless://'):
                return None

            without_proto = config_str[8:]

            if '@' not in without_proto:
                return None

            uuid_part, rest = without_proto.split('@', 1)

            server_part = rest.split('?', 1)[0].split('#')[0]

            if ':' in server_part:
                host, port = server_part.split(':', 1)
            else:
                host, port = server_part, '443'

            return {
                'type': 'vless',
                'host': host.strip(),
                'port': port.strip(),
                'original': config_str
            }
        except:
            return None
    
    def parse_trojan_config(self, config_str):
        try:
            if not config_str.startswith('trojan://'):
                return None
            
            without_proto = config_str[9:]
            
            if '@' not in without_proto:
                return None

            password, rest = without_proto.split('@', 1)

            server_part = rest.split('?', 1)[0].split('#')[0]

            if ':' in server_part:
                host, port = server_part.split(':', 1)
            else:
                host, port = server_part, '443'

            return {
                'type': 'trojan',
                'host': host.strip(),
                'port': port.strip(),
                'original': config_str
            }
        except:
            return None
    
    def parse_ss_config(self, config_str):
        try:
            if not config_str.startswith('ss://'):
                return None
            
            without_proto = config_str[5:]
            
            if '@' in without_proto:
                encoded_part, rest = without_proto.split('@', 1)
                
                if '#' in rest:
                    host_port, remark = rest.split('#', 1)
                else:
                    host_port, remark = rest, ''
                
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                    port = port.split('/')[0]
                else:
                    host, port = host_port, '443'
                
                return {
                    'type': 'ss',
                    'host': host,
                    'port': port,
                    'original': config_str
                }
            else:
                try:
                    if len(without_proto) % 4 != 0:
                        without_proto += '=' * (4 - len(without_proto) % 4)
                    decoded = base64.b64decode(without_proto).decode('utf-8')
                    
                    if '@' in decoded:
                        method_pass, host_port = decoded.split('@', 1)
                        
                        if ':' in host_port:
                            host, port = host_port.split(':', 1)
                            port = port.split('/')[0]
                        else:
                            host, port = host_port, '443'
                        
                        return {
                            'type': 'ss',
                            'host': host,
                            'port': port,
                            'original': config_str
                        }
                except:
                    pass
                
                return None
        except:
            return None
    
    def parse_generic_config(self, config_str):
        protocols = {
            'hysteria2://': 'hysteria2',
            'hy2://': 'hysteria2',
            'hysteria://': 'hysteria',
            'tuic://': 'tuic',
            'wireguard://': 'wireguard'
        }
        
        for proto_prefix, proto_name in protocols.items():
            if config_str.startswith(proto_prefix):
                try:
                    without_proto = config_str.replace(proto_prefix, '')
                    
                    host = None
                    port = '443'
                    
                    if '@' in without_proto:
                        parts = without_proto.split('@', 1)
                        if len(parts) == 2:
                            server_part = parts[1].split('#')[0].split('?')[0].split('/')[0]
                            if ':' in server_part:
                                host = server_part.split(':')[0]
                                port = server_part.split(':')[1]
                            else:
                                host = server_part
                    else:
                        server_part = without_proto.split('#')[0].split('?')[0].split('/')[0]
                        if ':' in server_part:
                            host = server_part.split(':')[0]
                            port = server_part.split(':')[1]
                        else:
                            host = server_part
                    
                    if host:
                        return {
                            'type': proto_name,
                            'host': host,
                            'port': port,
                            'original': config_str
                        }
                except:
                    pass
        
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
        else:
            return self.parse_generic_config(config_str)
    
    def classify_config(self, config_str):
        parsed = self.parse_config(config_str)
        if not parsed:
            return None, 'XX'

        country = self.real_detector.get_real_country(parsed)

        if not country or country == 'XX':
            return None, 'XX'

        return parsed, country
    
    def process_file(self, input_file, source_name):
        if not os.path.exists(input_file):
            return {}, 0, 0, 0
        
        configs = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    configs.append(line)
        
        results = {}
        failed = 0
        cdn_skipped = 0
        
        print(f"  Processing {len(configs)} configs from {source_name}...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_config = {}
            for config in configs:
                future = executor.submit(self.classify_config, config)
                future_to_config[future] = config
            
            processed = 0
            for future in as_completed(future_to_config):
                config = future_to_config[future]
                processed += 1
                if processed % 50 == 0:
                    print(f"    Progress: {processed}/{len(configs)}")
                
                try:
                    parsed, country = future.result(timeout=10)
                    if parsed and country and country != 'XX':
                        if country not in results:
                            results[country] = []
                        results[country].append(config)
                    else:
                        failed += 1
                except TimeoutError:
                    failed += 1
                except Exception as e:
                    failed += 1
        
        return results, len(configs), failed, cdn_skipped
    
    def save_country_files(self, country_results, total_processed, failed, cdn_skipped):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs('configs/country', exist_ok=True)
        
        categories = ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hysteria', 'tuic', 'wireguard', 'other']
        country_summary = {}
        
        for country, configs in country_results.items():
            if country == 'XX':
                continue
                
            country_dir = f"configs/country/{country}"
            os.makedirs(country_dir, exist_ok=True)
            
            categorized = {cat: [] for cat in categories}
            
            for config in configs:
                if config.startswith('vmess://'):
                    categorized['vmess'].append(config)
                elif config.startswith('vless://'):
                    categorized['vless'].append(config)
                elif config.startswith('trojan://'):
                    categorized['trojan'].append(config)
                elif config.startswith('ss://'):
                    categorized['ss'].append(config)
                elif config.startswith('hysteria2://') or config.startswith('hy2://'):
                    categorized['hysteria2'].append(config)
                elif config.startswith('hysteria://'):
                    categorized['hysteria'].append(config)
                elif config.startswith('tuic://'):
                    categorized['tuic'].append(config)
                elif config.startswith('wireguard://'):
                    categorized['wireguard'].append(config)
                else:
                    categorized['other'].append(config)
            
            all_configs = []
            for cat, cat_configs in categorized.items():
                if cat_configs:
                    filename = f"{country_dir}/{cat}.txt"
                    content = f"# {country} - {cat.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(cat_configs)}\n\n"
                    content += "\n".join(cat_configs)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                    all_configs.extend(cat_configs)
            
            if all_configs:
                filename = f"{country_dir}/all.txt"
                content = f"# {country} - All Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_configs)}\n\n"
                content += "\n".join(all_configs)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            meta = {
                'country': country,
                'total_configs': len(all_configs),
                'by_protocol': {cat: len(categorized[cat]) for cat in categories if categorized[cat]},
                'updated': timestamp
            }
            
            with open(f"{country_dir}/meta.json", 'w', encoding='utf-8') as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
            
            country_summary[country] = {
                'total': len(all_configs),
                'protocols': list(meta['by_protocol'].keys())
            }
        
        with open('configs/country/summary.json', 'w', encoding='utf-8') as f:
            json.dump(country_summary, f, ensure_ascii=False, indent=2)
        
        readme_content = f"""# 🌍 Country-Based Configurations
Last Updated: {timestamp}
Total Countries: {len(country_summary)}
Total Valid Configs: {sum(c['total'] for c in country_summary.values())}
Failed/Invalid: {failed}
CDN/Proxy Skipped: {cdn_skipped}

## 📊 Available Countries
"""
        for country, info in sorted(country_summary.items(), key=lambda x: x[1]['total'], reverse=True):
            readme_content += f"\n- **{country}**: {info['total']} configs ({', '.join(info['protocols'])})"
        
        with open('configs/country/README.md', 'w', encoding='utf-8') as f:
            f.write(readme_content)
        
        return len(country_summary), sum(c['total'] for c in country_summary.values())
    
    def update_geoip_database(self):
        try:
            if os.path.exists('geoip/GeoLite2-Country.mmdb'):
                mtime = datetime.fromtimestamp(os.path.getmtime('geoip/GeoLite2-Country.mmdb'))
                if datetime.now() - mtime < timedelta(days=7):
                    return True
            
            result = subprocess.run(
                ['geoipupdate', '-f', 'GeoIP.conf', '-d', 'geoip/'],
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0
        except:
            try:
                import urllib.request
                url = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb"
                os.makedirs('geoip', exist_ok=True)
                urllib.request.urlretrieve(url, 'geoip/GeoLite2-Country.mmdb')
                return True
            except:
                return False

def main():
    print("=" * 60)
    print("🌍 COUNTRY CLASSIFIER - REAL SERVER IP DETECTION")
    print("=" * 60)
    
    classifier = CountryClassifier()
    
    print("\n📥 Updating GeoIP database...")
    if classifier.update_geoip_database():
        print("✅ GeoIP database updated")
        classifier.init_geoip()
    else:
        print("⚠️ Using existing GeoIP database")
    
    print("\n📁 Processing combined configurations...")
    
    if not os.path.exists('configs/combined/all.txt'):
        print("❌ No combined configs found")
        return
    
    country_results = {}
    total_processed = 0
    total_failed = 0
    total_cdn_skipped = 0
    
    results, processed, failed, cdn_skipped = classifier.process_file(
        'configs/combined/all.txt', 'combined'
    )
    
    for country, configs in results.items():
        if country not in country_results:
            country_results[country] = []
        country_results[country].extend(configs)
    
    total_processed += processed
    total_failed += failed
    total_cdn_skipped += cdn_skipped
    
    print(f"\n📊 Classification Results:")
    print(f"  Total configs processed: {total_processed}")
    print(f"  Valid configs: {total_processed - total_failed - total_cdn_skipped}")
    print(f"  Failed/invalid: {total_failed}")
    print(f"  CDN/proxy skipped: {total_cdn_skipped}")
    
    real_countries = [c for c in country_results.keys() if c != 'XX']
    print(f"  Unique countries: {len(real_countries)}")
    
    if real_countries:
        country_count, total_saved = classifier.save_country_files(
            country_results, total_processed, total_failed, total_cdn_skipped
        )
        print(f"\n✅ Saved configurations for {country_count} countries")
        print(f"  Total configs by country: {total_saved}")
    
    classifier.save_cache()
    
    top_countries = sorted(
        [(c, len(configs)) for c, configs in country_results.items() if c != 'XX'],
        key=lambda x: x[1], reverse=True
    )[:10]
    
    if top_countries:
        print("\n🏆 Top 10 Countries:")
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
    
    print("\n" + "=" * 60)
    print("✅ COUNTRY CLASSIFICATION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
