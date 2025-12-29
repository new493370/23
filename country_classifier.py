import os
import re
import json
import base64
import hashlib
import socket
import pickle
import threading
import concurrent.futures
import requests
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self):
        self.lock = threading.Lock()
    
    def parse_vmess(self, config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            config_data = json.loads(base64.b64decode(base64_part).decode('utf-8'))
            
            address = config_data.get('add', '')
            
            return {
                'protocol': 'vmess',
                'address': address,
                'port': int(config_data.get('port', 0)),
                'raw': config_str
            }
        except:
            return None
    
    def parse_vless(self, config_str):
        try:
            parsed = urlparse(config_str)
            netloc = parsed.netloc
            
            if '@' in netloc:
                _, server_part = netloc.split('@', 1)
            else:
                server_part = netloc
            
            if ':' in server_part:
                host = server_part.split(':')[0]
            else:
                host = server_part
            
            port = 0
            if ':' in server_part:
                port_part = server_part.split(':')[1]
                if '?' in port_part:
                    port = int(port_part.split('?')[0])
                else:
                    port = int(port_part)
            
            return {
                'protocol': 'vless',
                'address': host,
                'port': port,
                'raw': config_str
            }
        except:
            return None
    
    def parse_trojan(self, config_str):
        try:
            parsed = urlparse(config_str)
            netloc = parsed.netloc
            
            if '@' in netloc:
                _, server_part = netloc.split('@', 1)
            else:
                server_part = netloc
            
            if ':' in server_part:
                host = server_part.split(':')[0]
            else:
                host = server_part
            
            port = 0
            if ':' in server_part:
                port_part = server_part.split(':')[1]
                if '#' in port_part:
                    port = int(port_part.split('#')[0])
                else:
                    port = int(port_part)
            
            return {
                'protocol': 'trojan',
                'address': host,
                'port': port,
                'raw': config_str
            }
        except:
            return None
    
    def parse_ss(self, config_str):
        try:
            parts = config_str.split('#', 1)
            base_part = parts[0][5:]
            
            if '@' not in base_part:
                if len(base_part) % 4 != 0:
                    base_part += '=' * (4 - len(base_part) % 4)
                decoded = base64.b64decode(base_part).decode('utf-8')
                if '@' in decoded:
                    _, server_part = decoded.split('@', 1)
                else:
                    return None
            else:
                _, server_part = base_part.split('@', 1)
            
            if ':' in server_part:
                host = server_part.split(':')[0]
                port = int(server_part.split(':')[1])
            else:
                return None
            
            return {
                'protocol': 'ss',
                'address': host,
                'port': port,
                'raw': config_str
            }
        except:
            return None
    
    def parse_hysteria(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            
            if ':' in host_port:
                host = host_port.split(':')[0]
                port = int(host_port.split(':')[1])
            else:
                return None
            
            return {
                'protocol': 'hysteria',
                'address': host,
                'port': port,
                'raw': config_str
            }
        except:
            return None
    
    def parse_tuic(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            
            if ':' in host_port:
                host = host_port.split(':')[0]
                port = int(host_port.split(':')[1])
            else:
                return None
            
            return {
                'protocol': 'tuic',
                'address': host,
                'port': port,
                'raw': config_str
            }
        except:
            return None
    
    def parse_wireguard(self, config_str):
        try:
            parsed = urlparse(config_str)
            params = parsed.query
            host = ''
            
            for param in params.split('&'):
                if param.startswith('address='):
                    host = param[8:].split(':')[0]
                    break
            
            return {
                'protocol': 'wireguard',
                'address': host,
                'port': 51820,
                'raw': config_str
            }
        except:
            return None
    
    def is_valid_ipv4(self, ip):
        if not ip:
            return False
        
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if not re.match(ipv4_pattern, ip):
            return False
        
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except:
                return False
        
        return True
    
    def parse_config(self, config_str):
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            return self.parse_vmess(config_str)
        elif config_str.startswith('vless://'):
            return self.parse_vless(config_str)
        elif config_str.startswith('trojan://'):
            return self.parse_trojan(config_str)
        elif config_str.startswith('ss://'):
            return self.parse_ss(config_str)
        elif config_str.startswith('hysteria://') or config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
            return self.parse_hysteria(config_str)
        elif config_str.startswith('tuic://'):
            return self.parse_tuic(config_str)
        elif config_str.startswith('wireguard://'):
            return self.parse_wireguard(config_str)
        
        return None

class GeoIPClassifier:
    def __init__(self):
        self.maxmind_db = None
        self.maxmind_db_path = 'GeoLite2-Country.mmdb'
        self.ipapi_cache = {}
        self.cache_file = 'geoip_cache.pkl'
        self.lock = threading.Lock()
        self.load_cache()
        self.load_maxmind_db()
    
    def load_maxmind_db(self):
        try:
            if os.path.exists(self.maxmind_db_path):
                import geoip2.database
                self.maxmind_db = geoip2.database.Reader(self.maxmind_db_path)
                logger.info("MaxMind GeoIP database loaded")
            else:
                self.download_maxmind_db()
        except ImportError:
            logger.warning("geoip2 library not available, using ip-api.com only")
        except Exception as e:
            logger.warning(f"Failed to load MaxMind database: {e}")
    
    def download_maxmind_db(self):
        try:
            urls = [
                "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb",
                "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
            ]
            
            for url in urls:
                try:
                    logger.info(f"Downloading GeoIP database from: {url}")
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        with open(self.maxmind_db_path, 'wb') as f:
                            f.write(response.content)
                        self.load_maxmind_db()
                        return
                except:
                    continue
            logger.warning("Could not download GeoIP database")
        except:
            pass
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    self.ipapi_cache = pickle.load(f)
        except:
            self.ipapi_cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.ipapi_cache, f)
        except:
            pass
    
    def get_country_by_maxmind(self, ip):
        try:
            if self.maxmind_db:
                response = self.maxmind_db.country(ip)
                return response.country.iso_code or "UNKNOWN"
        except:
            pass
        return None
    
    def get_country_by_ipapi(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode,as", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('countryCode', 'UNKNOWN')
                    asn = data.get('as', '')
                    return country
        except:
            pass
        return "UNKNOWN"
    
    def validate_asn_country(self, ip, detected_country):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode,as", timeout=5)
            if response.status_code == 200:
                data = response.json()
                api_country = data.get('countryCode', '')
                asn = data.get('as', '')
                
                common_us_asns = ['AS14618', 'AS15169', 'AS16509', 'AS20473', 'AS3356']
                if detected_country == 'US' and api_country != 'US' and any(asn_item in asn for asn_item in common_us_asns):
                    return api_country
        except:
            pass
        return detected_country
    
    def get_country(self, ip):
        with self.lock:
            if ip in self.ipapi_cache:
                return self.ipapi_cache[ip]
        
        country = None
        
        maxmind_country = self.get_country_by_maxmind(ip)
        if maxmind_country and maxmind_country != "UNKNOWN":
            country = maxmind_country
        
        if not country or country == "UNKNOWN":
            country = self.get_country_by_ipapi(ip)
        
        country = self.validate_asn_country(ip, country)
        
        with self.lock:
            self.ipapi_cache[ip] = country
        
        return country

class CountryClassifier:
    def __init__(self, max_workers=30):
        self.parser = ConfigParser()
        self.geoip = GeoIPClassifier()
        self.max_workers = max_workers
        self.results_lock = threading.Lock()
        self.results = {}
        self.stats = {
            'total': 0,
            'ip_based': 0,
            'domain_based': 0,
            'by_country': {},
            'by_protocol': {}
        }
    
    def process_single_config(self, config_str):
        try:
            parsed = self.parser.parse_config(config_str)
            if not parsed:
                return None
            
            address = parsed.get('address', '')
            if not address:
                return None
            
            is_ip = self.parser.is_valid_ipv4(address)
            
            if not is_ip:
                return {
                    'config': config_str,
                    'parsed': parsed,
                    'ip': None,
                    'country': 'DOMAIN',
                    'is_ip': False,
                    'address': address
                }
            
            country = self.geoip.get_country(address)
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': address,
                'country': country,
                'is_ip': True,
                'address': address
            }
        except Exception as e:
            logger.debug(f"Failed to process config: {e}")
            return None
    
    def process_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations...")
        
        self.results = {}
        self.stats = {
            'total': len(configs),
            'ip_based': 0,
            'domain_based': 0,
            'by_country': {},
            'by_protocol': {}
        }
        
        unique_configs = []
        seen = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen:
                seen.add(config_hash)
                unique_configs.append(config)
        
        logger.info(f"After deduplication: {len(unique_configs)} unique configs")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_config = {executor.submit(self.process_single_config, config): config for config in unique_configs}
            
            completed = 0
            for future in concurrent.futures.as_completed(future_to_config):
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Processed {completed}/{len(unique_configs)} configs")
                
                result = future.result()
                if result:
                    with self.results_lock:
                        if result['is_ip']:
                            self.stats['ip_based'] += 1
                        else:
                            self.stats['domain_based'] += 1
                        
                        country = result['country']
                        protocol = result['parsed']['protocol']
                        
                        if country not in self.results:
                            self.results[country] = {}
                        
                        if protocol not in self.results[country]:
                            self.results[country][protocol] = []
                        
                        self.results[country][protocol].append(result['config'])
                        
                        self.stats['by_country'][country] = self.stats['by_country'].get(country, 0) + 1
                        self.stats['by_protocol'][protocol] = self.stats['by_protocol'].get(protocol, 0) + 1
        
        self.geoip.save_cache()
        
        return {
            'results': self.results,
            'stats': self.stats
        }
    
    def save_results(self, results, output_dir='configs/country'):
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        ip_based_configs = []
        
        for country, protocols in results['results'].items():
            if country == 'DOMAIN':
                continue
                
            country_dir = os.path.join(output_dir, country)
            os.makedirs(country_dir, exist_ok=True)
            
            all_country_configs = []
            
            for protocol, configs in protocols.items():
                if configs:
                    protocol_file = os.path.join(country_dir, f"{protocol}.txt")
                    content = f"# {country} - {protocol.upper()} Configurations\n"
                    content += f"# Updated: {timestamp}\n"
                    content += f"# Count: {len(configs)}\n"
                    content += f"# Country Code: {country}\n\n"
                    content += "\n".join(configs)
                    
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        f.write(content)
                    
                    all_country_configs.extend(configs)
                    ip_based_configs.extend(configs)
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                content = f"# All Configurations for {country}\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(all_country_configs)}\n"
                content += f"# Country Code: {country}\n\n"
                content += "\n".join(all_country_configs)
                
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        if 'DOMAIN' in results['results']:
            domain_dir = os.path.join(output_dir, 'DOMAIN')
            os.makedirs(domain_dir, exist_ok=True)
            
            domain_configs = []
            for protocol, configs in results['results']['DOMAIN'].items():
                domain_configs.extend(configs)
            
            if domain_configs:
                domain_file = os.path.join(domain_dir, "all.txt")
                content = f"# Domain-Based Configurations\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Total Count: {len(domain_configs)}\n"
                content += "# Note: These configs use domain names instead of IP addresses\n\n"
                content += "\n".join(domain_configs)
                
                with open(domain_file, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        ip_summary_file = os.path.join(output_dir, "ip_based_summary.txt")
        with open(ip_summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# IP-Based Configurations Summary\n")
            f.write(f"# Updated: {timestamp}\n\n")
            f.write(f"Total IP-based configs: {len(ip_based_configs)}\n\n")
            
            country_stats = {}
            for config in ip_based_configs:
                for country in results['results']:
                    if country == 'DOMAIN':
                        continue
                    for protocol_configs in results['results'][country].values():
                        if config in protocol_configs:
                            country_stats[country] = country_stats.get(country, 0) + 1
                            break
            
            f.write("IP-Based Configs by Country:\n")
            for country, count in sorted(country_stats.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {country}: {count}\n")
        
        stats_file = os.path.join(output_dir, "stats.json")
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(results['stats'], f, indent=2)
        
        summary_file = os.path.join(output_dir, "summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Country Classification Summary\n")
            f.write(f"# Updated: {timestamp}\n\n")
            f.write(f"Total configs processed: {results['stats']['total']}\n")
            f.write(f"IP-based configs: {results['stats']['ip_based']}\n")
            f.write(f"Domain-based configs: {results['stats']['domain_based']}\n\n")
            
            f.write("IP-Based Configs by Country:\n")
            ip_countries = {k: v for k, v in results['stats']['by_country'].items() if k != 'DOMAIN'}
            for country, count in sorted(ip_countries.items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {country}: {count}\n")
            
            f.write("\nBy Protocol:\n")
            for protocol, count in sorted(results['stats']['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count}\n")
        
        logger.info(f"Results saved to {output_dir}")

def read_all_configs():
    configs = []
    
    combined_file = 'configs/combined/all.txt'
    if os.path.exists(combined_file):
        try:
            with open(combined_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        configs.append(line)
        except:
            pass
    
    if not configs:
        sources = [
            'configs/telegram/all.txt',
            'configs/github/all.txt'
        ]
        
        for filepath in sources:
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                configs.append(line)
                except:
                    pass
    
    return configs

def main():
    print("=" * 60)
    print("IP-BASED COUNTRY CONFIG CLASSIFIER")
    print("=" * 60)
    
    try:
        configs = read_all_configs()
        if not configs:
            logger.error("No configurations found to process")
            return
        
        logger.info(f"Found {len(configs)} configurations")
        
        classifier = CountryClassifier(max_workers=30)
        start_time = time.time()
        
        results = classifier.process_configs(configs)
        
        elapsed_time = time.time() - start_time
        
        classifier.save_results(results)
        
        print(f"\n✅ CLASSIFICATION COMPLETE")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        print(f"Total configs: {results['stats']['total']}")
        print(f"IP-based configs: {results['stats']['ip_based']}")
        print(f"Domain-based configs: {results['stats']['domain_based']}")
        
        print(f"\n📊 IP-Based Configs by Country:")
        ip_countries = {k: v for k, v in results['stats']['by_country'].items() if k != 'DOMAIN'}
        top_countries = sorted(ip_countries.items(), key=lambda x: x[1], reverse=True)[:15]
        
        for country, count in top_countries:
            print(f"  {country}: {count} configs")
        
        print(f"\n📁 Output saved to: configs/country/")
        print("=" * 60)
        
    except Exception as e:
        logger.error(f"Error in main: {e}")

if __name__ == "__main__":
    main()
