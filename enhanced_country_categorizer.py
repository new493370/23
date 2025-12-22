import os
import re
import json
import base64
import socket
import time
import logging
import geoip2.database
import requests
from datetime import datetime
import concurrent.futures
from threading import Lock
from tqdm import tqdm
import pickle
from collections import defaultdict
import urllib.parse

class EnhancedCountryCategorizer:
    def __init__(self, db_path="GeoLite2-Country.mmdb", skipped_countries=None):
        self.db_path = db_path
        self.geoip_reader = None
        self.geoip_lock = Lock()
        self.dns_lock = Lock()
        self.host_lock = Lock()
        
        self.cache_file = "country_cache.pkl"
        self.dns_cache = self.load_cache('dns_cache', {})
        self.geoip_cache = self.load_cache('geoip_cache', {})
        self.host_cache = self.load_cache('host_cache', {})
        
        self.skipped_countries = skipped_countries or ['CN', 'TW', 'RU', 'KP', 'IR', 'SY', 'CU', 'SD']
        
        self.cdn_domains = [
            'cloudflare.com', 'cloudflare.net',
            'fastly.net', 'fastly.com',
            'akamai.net', 'akamaihd.net',
            'cloudfront.net', 'aws.amazon.com',
            'azureedge.net', 'azure.com',
            'googleusercontent.com', 'googleapis.com',
            'cdn77.org', 'cdn77.net',
            'cachefly.net', 'incapdns.net'
        ]
        
        self.protocol_patterns = {
            'vmess': r'vmess://',
            'vless': r'vless://',
            'trojan': r'trojan://',
            'ss': r'ss://',
            'hysteria2': r'hysteria2://|hy2://',
            'hysteria': r'hysteria://',
            'tuic': r'tuic://',
            'wireguard': r'wireguard://',
            'reality': r'reality://'
        }
        
        self.init_geoip()
        
        socket.setdefaulttimeout(10)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('country_categorizer.log', encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_cache(self, key, default=None):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'rb') as f:
                    cache = pickle.load(f)
                    if not isinstance(cache, dict):
                        return default if default is not None else {}
                    return cache.get(key, default)
            except Exception:
                return default if default is not None else {}
        return default if default is not None else {}
    
    def save_cache(self):
        cache = {
            'dns_cache': self.dns_cache,
            'geoip_cache': self.geoip_cache,
            'host_cache': self.host_cache
        }
        try:
            with self.dns_lock, self.geoip_lock, self.host_lock:
                with open(self.cache_file, 'wb') as f:
                    pickle.dump(cache, f)
        except Exception as e:
            self.logger.error(f"Failed to save cache: {e}")
    
    def init_geoip(self):
        possible_paths = [
            self.db_path,
            "GeoLite2-Country.mmdb",
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            "/var/lib/GeoIP/GeoLite2-Country.mmdb",
            os.path.expanduser("~/.config/geoip/GeoLite2-Country.mmdb")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    self.geoip_reader = geoip2.database.Reader(path)
                    self.logger.info(f"Loaded GeoIP database from {path}")
                    return
                except Exception as e:
                    self.logger.warning(f"Failed to load GeoIP from {path}: {e}")
        
        self.logger.warning("No GeoIP database found!")
        self.geoip_reader = None
    
    def download_geoip_db(self):
        if self.geoip_reader is not None:
            return True
        
        try:
            self.logger.info("Downloading GeoIP database...")
            
            sources = [
                "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb",
                "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
                "https://cdn.jsdelivr.net/gh/Hackl0us/GeoIP2-CN@release/Country.mmdb"
            ]
            
            for url in sources:
                try:
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        with open("Country.mmdb", "wb") as f:
                            f.write(response.content)
                        
                        self.geoip_reader = geoip2.database.Reader("Country.mmdb")
                        self.logger.info(f"Downloaded GeoIP database from {url}")
                        return True
                except Exception as e:
                    self.logger.warning(f"Failed to download from {url}: {e}")
            
            return False
        except Exception as e:
            self.logger.error(f"Failed to download GeoIP: {e}")
            return False
    
    def get_country_from_ip(self, ip):
        if not self.geoip_reader:
            with self.geoip_lock:
                if not self.geoip_reader:
                    if not hasattr(self, 'geoip_downloading'):
                        self.geoip_downloading = False
                    if not self.geoip_downloading:
                        self.geoip_downloading = True
                        try:
                            self.download_geoip_db()
                        finally:
                            self.geoip_downloading = False
                    if not self.geoip_reader:
                        return "NO_GEOIP_DB"
        
        try:
            with self.geoip_lock:
                if ip in self.geoip_cache:
                    return self.geoip_cache[ip]
            
            response = self.geoip_reader.country(ip)
            country_code = response.country.iso_code
            
            if not country_code:
                country_code = "UNKNOWN"
            
            with self.geoip_lock:
                self.geoip_cache[ip] = country_code
            
            return country_code
        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return "UNKNOWN"
    
    def extract_host_info(self, config_str):
        result = {
            'host': None,
            'port': None,
            'sni': None,
            'protocol': self.get_protocol(config_str),
            'original': config_str
        }
        
        try:
            if config_str.startswith('vmess://'):
                try:
                    b = config_str[8:]
                    if len(b) % 4 != 0:
                        b += '=' * (4 - len(b) % 4)
                    d = json.loads(base64.b64decode(b).decode())
                    result['host'] = d.get('add') or d.get('host') or d.get('sni')
                    result['port'] = d.get('port')
                    result['sni'] = d.get('sni') or d.get('host')
                except:
                    result['host'] = "INVALID_VMESS"
            
            elif config_str.startswith('vless://'):
                match = re.search(r'@([^:/#?]+):(\d+)', config_str)
                if match:
                    result['host'], result['port'] = match.groups()
                
                sni_match = re.search(r'&sni=([^&#]+)', config_str)
                if sni_match:
                    result['sni'] = sni_match.group(1)
            
            elif config_str.startswith('trojan://'):
                match = re.search(r'@([^:/#?]+):(\d+)', config_str)
                if match:
                    result['host'], result['port'] = match.groups()
                
                sni_match = re.search(r'&sni=([^&#]+)', config_str)
                if sni_match:
                    result['sni'] = sni_match.group(1)
            
            elif config_str.startswith('ss://'):
                try:
                    parts = config_str.split('#', 1)
                    base_part = parts[0][5:]
                    
                    if '@' in base_part:
                        encoded_method_pass, server_part = base_part.split('@', 1)
                        if ':' in server_part:
                            host_port = server_part.split(':', 1)
                            result['host'] = host_port[0]
                            result['port'] = host_port[1] if len(host_port) > 1 else None
                    else:
                        if len(base_part) % 4 != 0:
                            base_part += '=' * (4 - len(base_part) % 4)
                        decoded = base64.b64decode(base_part).decode()
                        if '@' in decoded:
                            method_pass, server_part = decoded.split('@', 1)
                            if ':' in server_part:
                                host_port = server_part.split(':', 1)
                                result['host'] = host_port[0]
                                result['port'] = host_port[1] if len(host_port) > 1 else None
                except:
                    result['host'] = "INVALID_SS"
            
            elif config_str.startswith(('hysteria2://', 'hy2://', 'hysteria://', 'tuic://')):
                match = re.search(r'@([^:/#?]+):(\d+)', config_str)
                if match:
                    result['host'], result['port'] = match.groups()
            
            elif config_str.startswith('wireguard://'):
                try:
                    decoded = urllib.parse.unquote(config_str[12:])
                    params = dict(urllib.parse.parse_qsl(decoded))
                    
                    endpoint = params.get('Endpoint')
                    if endpoint and ':' in endpoint:
                        host_port = endpoint.split(':', 1)
                        result['host'] = host_port[0]
                        result['port'] = host_port[1] if len(host_port) > 1 else None
                except:
                    result['host'] = "INVALID_WG"
            
            if result['host']:
                result['host'] = result['host'].strip()
                if result['host'].startswith('[') and result['host'].endswith(']'):
                    result['host'] = result['host'][1:-1]
        
        except Exception as e:
            self.logger.debug(f"Error parsing config: {e}")
            result['host'] = "PARSE_ERROR"
        
        return result
    
    def get_protocol(self, config_str):
        for proto, pattern in self.protocol_patterns.items():
            if re.search(pattern, config_str, re.IGNORECASE):
                return proto
        return "other"
    
    def resolve_host_to_ip(self, hostname, retries=3):
        if not hostname or hostname in ["INVALID", "NO_HOST", "PARSE_ERROR"]:
            return None
        
        with self.dns_lock:
            if hostname in self.dns_cache:
                cached_ip = self.dns_cache[hostname]
                if cached_ip != "FAILED":
                    return cached_ip
        
        for attempt in range(retries):
            try:
                info = socket.getaddrinfo(hostname, None, 
                                        socket.AF_UNSPEC, 
                                        socket.SOCK_STREAM)
                
                for res in info:
                    af, socktype, proto, canonname, sa = res
                    if af == socket.AF_INET:
                        ip = sa[0]
                        with self.dns_lock:
                            self.dns_cache[hostname] = ip
                        return ip
                
                if info:
                    ip = info[0][4][0]
                    with self.dns_lock:
                        self.dns_cache[hostname] = ip
                    return ip
                    
            except (socket.gaierror, socket.timeout) as e:
                if attempt == retries - 1:
                    self.logger.debug(f"DNS failed for {hostname}: {e}")
                    with self.dns_lock:
                        self.dns_cache[hostname] = "FAILED"
                    return None
                time.sleep(1 * (attempt + 1))
        
        return None
    
    def is_cdn_or_proxy(self, hostname):
        if not hostname:
            return False
        
        hostname_lower = hostname.lower()
        
        for cdn in self.cdn_domains:
            if cdn in hostname_lower or hostname_lower.endswith('.' + cdn):
                return True
        
        cdn_patterns = [
            r'\.cdn\.',
            r'\.cache\.',
            r'\.proxy\.',
            r'\.lb\.',
            r'\.edge\.',
            r'\.frontend\.',
            r'^cdn\.',
            r'^proxy\.',
            r'^edge\.'
        ]
        
        for pattern in cdn_patterns:
            if re.search(pattern, hostname_lower):
                return True
        
        return False
    
    def get_cdn_provider(self, hostname):
        if not hostname:
            return None
        
        hostname_lower = hostname.lower()
        
        cdn_providers = {
            'cloudflare': ['cloudflare.com', 'cloudflare.net'],
            'fastly': ['fastly.net', 'fastly.com'],
            'akamai': ['akamai.net', 'akamaihd.net'],
            'aws': ['cloudfront.net', 'aws.amazon.com'],
            'azure': ['azureedge.net', 'azure.com'],
            'google': ['googleusercontent.com', 'googleapis.com']
        }
        
        for provider, domains in cdn_providers.items():
            for domain in domains:
                if domain in hostname_lower:
                    return provider
        
        return 'unknown'
    
    def get_real_ip_behind_cdn(self, hostname):
        if 'cloudflare' in hostname.lower():
            return None
        
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['1.1.1.1', '1.0.0.1']
            answers = resolver.resolve(hostname, 'A')
            for rdata in answers:
                return str(rdata)
        except:
            pass
        
        services = [
            f"https://dns.google/resolve?name={hostname}&type=A",
            f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A"
        ]
        
        for service in services:
            try:
                response = requests.get(service, headers={'Accept': 'application/dns-json'}, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if 'Answer' in data:
                        for answer in data['Answer']:
                            if answer['type'] == 1:
                                return answer['data']
            except:
                continue
        
        return None
    
    def get_country_for_host(self, host_info):
        host = host_info.get('host')
        
        if not host or host.startswith(('INVALID_', 'PARSE_')):
            return {'country': 'INVALID', 'cdn': False, 'ip': None, 'original_host': host}
        
        if host in ["NO_HOST", "UNKNOWN_PROTOCOL"]:
            return {'country': 'NO_HOST', 'cdn': False, 'ip': None, 'original_host': host}
        
        with self.host_lock:
            if host in self.host_cache:
                cached_result = self.host_cache[host]
                if isinstance(cached_result, dict):
                    return cached_result
                return {'country': cached_result, 'cdn': False, 'ip': None, 'original_host': host}
        
        is_cdn = self.is_cdn_or_proxy(host)
        cdn_provider = self.get_cdn_provider(host) if is_cdn else None
        
        if is_cdn:
            real_ip = self.get_real_ip_behind_cdn(host)
            if real_ip:
                ip_to_check = real_ip
                self.logger.debug(f"Found real IP behind CDN {host}: {real_ip}")
                is_behind_cdn = True
            else:
                ip_to_check = self.resolve_host_to_ip(host)
                is_behind_cdn = False
                if not ip_to_check:
                    result = {
                        'country': "CDN_PROXY",
                        'cdn': True,
                        'cdn_provider': cdn_provider,
                        'original_host': host,
                        'ip': None
                    }
                    with self.host_lock:
                        self.host_cache[host] = result
                    return result
        else:
            ip_to_check = self.resolve_host_to_ip(host)
            is_behind_cdn = False
            if not ip_to_check:
                result = {
                    'country': "DNS_FAIL",
                    'cdn': False,
                    'original_host': host,
                    'ip': None
                }
                with self.host_lock:
                    self.host_cache[host] = result
                return result
        
        country_code = self.get_country_from_ip(ip_to_check)
        
        if country_code in self.skipped_countries:
            country_code = "SKIPPED"
        
        result = {
            'country': country_code,
            'cdn': is_behind_cdn,
            'ip': ip_to_check,
            'original_host': host
        }
        
        if is_behind_cdn and cdn_provider:
            result['cdn_provider'] = cdn_provider
        
        with self.host_lock:
            self.host_cache[host] = result
        
        return result
    
    def process_configs_threaded(self, configs, max_workers=None):
        if max_workers is None:
            max_workers = min(32, (os.cpu_count() or 1) * 4)
        
        results = defaultdict(list)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_config = {
                executor.submit(self.process_single_config, config): config 
                for config in configs
            }
            
            with tqdm(total=len(configs), desc="Categorizing by country", 
                     disable=(len(configs) > 10000)) as pbar:
                for future in concurrent.futures.as_completed(future_to_config):
                    try:
                        result, config_info = future.result()
                        country_code = result.get('country', 'UNKNOWN')
                        results[country_code].append(config_info)
                    except Exception as e:
                        self.logger.error(f"Error processing config: {e}")
                        results["ERROR"].append({
                            'config': future_to_config[future],
                            'error': str(e)
                        })
                    finally:
                        pbar.update(1)
        
        return results
    
    def process_single_config(self, config_str):
        host_info = self.extract_host_info(config_str)
        result = self.get_country_for_host(host_info)
        
        country_code = result.get('country', 'UNKNOWN')
        
        config_info = {
            'config': config_str,
            'host': host_info['host'],
            'port': host_info['port'],
            'protocol': host_info['protocol'],
            'country': country_code,
            'full_result': result
        }
        
        return result, config_info
    
    def save_optimized_results(self, results):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        output_dir = 'configs/country'
        os.makedirs(output_dir, exist_ok=True)
        
        country_stats = {}
        cdn_stats = defaultdict(int)
        
        for country, configs in results.items():
            if not configs:
                continue
            
            country_stats[country] = len(configs)
            
            for config_info in configs:
                if isinstance(config_info, dict) and config_info.get('full_result'):
                    full_result = config_info['full_result']
                    if isinstance(full_result, dict) and full_result.get('cdn'):
                        provider = full_result.get('cdn_provider', 'unknown')
                        cdn_stats[provider] += 1
            
            by_protocol = defaultdict(list)
            for config_info in configs:
                if isinstance(config_info, dict):
                    proto = config_info.get('protocol', 'unknown')
                    by_protocol[proto].append(config_info['config'])
                else:
                    by_protocol['unknown'].append(str(config_info))
            
            country_dir = os.path.join(output_dir, country)
            os.makedirs(country_dir, exist_ok=True)
            
            all_file = os.path.join(country_dir, 'all.txt')
            with open(all_file, 'w', encoding='utf-8') as f:
                f.write(f"# {country} - All Configurations\n")
                f.write(f"# Updated: {timestamp}\n")
                f.write(f"# Count: {len(configs)}\n\n")
                
                for proto in sorted(by_protocol.keys()):
                    if by_protocol[proto]:
                        f.write(f"\n# {proto.upper()} ({len(by_protocol[proto])})\n")
                        f.write("\n".join(by_protocol[proto]))
                        f.write("\n")
            
            for proto, config_list in by_protocol.items():
                if len(config_list) >= 10:
                    proto_file = os.path.join(country_dir, f"{proto}.txt")
                    with open(proto_file, 'w', encoding='utf-8') as f:
                        f.write(f"# {country} - {proto.upper()}\n")
                        f.write(f"# Updated: {timestamp}\n")
                        f.write(f"# Count: {len(config_list)}\n\n")
                        f.write("\n".join(config_list))
        
        summary_file = os.path.join(output_dir, 'summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            summary = {
                'timestamp': timestamp,
                'total_configs': sum(country_stats.values()),
                'country_stats': dict(sorted(
                    country_stats.items(),
                    key=lambda x: x[1],
                    reverse=True
                )),
                'cdn_stats': dict(cdn_stats),
                'countries': len(country_stats)
            }
            json.dump(summary, f, indent=2)
        
        csv_file = os.path.join(output_dir, 'stats.csv')
        with open(csv_file, 'w', encoding='utf-8') as f:
            f.write("Country,Count,Percentage\n")
            total = sum(country_stats.values())
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total * 100) if total > 0 else 0
                f.write(f"{country},{count},{percentage:.2f}%\n")
        
        cdn_csv_file = os.path.join(output_dir, 'cdn_stats.csv')
        with open(cdn_csv_file, 'w', encoding='utf-8') as f:
            f.write("CDN_Provider,Count\n")
            for provider, count in sorted(cdn_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"{provider},{count}\n")
        
        self.save_cache()
        
        return country_stats
    
    def run(self):
        self.logger.info("Starting enhanced country categorization...")
        
        configs = self.read_all_combined_configs()
        if not configs:
            self.logger.error("No configurations found!")
            return
        
        self.logger.info(f"Found {len(configs)} configurations")
        
        results = self.process_configs_threaded(configs)
        
        stats = self.save_optimized_results(results)
        
        self.print_summary(stats)
    
    def read_all_combined_configs(self):
        configs = []
        combined_dir = 'configs/combined'
        
        if not os.path.exists(combined_dir):
            self.logger.error(f"Directory {combined_dir} not found!")
            return configs
        
        all_file = os.path.join(combined_dir, 'all.txt')
        if os.path.exists(all_file):
            with open(all_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        configs.append(line)
        
        if not configs:
            for filename in os.listdir(combined_dir):
                if filename.endswith('.txt'):
                    filepath = os.path.join(combined_dir, filename)
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
        
        return list(set(configs))
    
    def print_summary(self, stats):
        print("=" * 70)
        print("ENHANCED COUNTRY CATEGORIZATION SUMMARY")
        print("=" * 70)
        
        total = sum(stats.values())
        print(f"Total configurations processed: {total}")
        print(f"Countries identified: {len(stats)}")
        
        print("\nTop 10 countries:")
        print("-" * 40)
        print(f"{'Country':<10} {'Count':<10} {'%':<10}")
        print("-" * 40)
        
        sorted_stats = sorted(stats.items(), key=lambda x: x[1], reverse=True)
        for country, count in sorted_stats[:10]:
            percentage = (count / total * 100) if total > 0 else 0
            print(f"{country:<10} {count:<10} {percentage:<10.2f}")
        
        errors = sum(count for country, count in stats.items() 
                    if country in ['INVALID', 'DNS_FAIL', 'NO_HOST', 'PARSE_ERROR'])
        skipped = stats.get('SKIPPED', 0)
        cdn = stats.get('CDN_PROXY', 0)
        
        print(f"\nErrors/Invalid: {errors}")
        print(f"Skipped countries: {skipped}")
        print(f"CDN/Proxy detected: {cdn}")
        print("=" * 70)

def main():
    try:
        categorizer = EnhancedCountryCategorizer()
        categorizer.run()
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
