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
    
    def extract_domain_from_url(self, url):
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                netloc = parsed.netloc
                if '@' in netloc:
                    netloc = netloc.split('@')[-1]
                if ':' in netloc:
                    netloc = netloc.split(':')[0]
                return netloc
        except:
            pass
        return ''
    
    def parse_vmess(self, config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            config_data = json.loads(base64.b64decode(base64_part).decode('utf-8'))
            
            address = config_data.get('add', '')
            host = config_data.get('host', '')
            sni = config_data.get('sni', '')
            
            target_host = address
            if host and self.is_domain(host):
                target_host = host
            elif sni and self.is_domain(sni):
                target_host = sni
            
            return {
                'protocol': 'vmess',
                'host': address,
                'port': int(config_data.get('port', 0)),
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'ps': config_data.get('ps', '')
            }
        except:
            return None
    
    def parse_vless(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('?')[0]) if '?' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            host_param = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            elif 'host' in query_params:
                host_param = query_params['host'][0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            elif host_param and self.is_domain(host_param):
                target_host = host_param
            
            return {
                'protocol': 'vless',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni,
                'host_param': host_param
            }
        except:
            return None
    
    def parse_trojan(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc.split('@')[-1]
            host, port_str = host_port.split(':')
            port = int(port_str.split('#')[0]) if '#' in port_str else int(port_str)
            
            query_params = parse_qs(parsed.query)
            sni = ''
            
            if 'sni' in query_params:
                sni = query_params['sni'][0]
            
            target_host = host
            if sni and self.is_domain(sni):
                target_host = sni
            
            return {
                'protocol': 'trojan',
                'host': host,
                'port': port,
                'target_host': target_host,
                'raw': config_str,
                'sni': sni
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
                    method_pass, server_part = decoded.split('@', 1)
                else:
                    return None
            else:
                encoded_method_pass, server_part = base_part.split('@', 1)
                
            server, port_str = server_part.split(':', 1)
            port = int(port_str)
            
            return {
                'protocol': 'ss',
                'host': server,
                'port': port,
                'target_host': server,
                'raw': config_str
            }
        except:
            return None
    
    def parse_hysteria(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            return {
                'protocol': 'hysteria',
                'host': host,
                'port': port,
                'target_host': host,
                'raw': config_str
            }
        except:
            return None
    
    def parse_tuic(self, config_str):
        try:
            parsed = urlparse(config_str)
            host_port = parsed.netloc
            host, port_str = host_port.split(':')
            port = int(port_str)
            
            return {
                'protocol': 'tuic',
                'host': host,
                'port': port,
                'target_host': host,
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
                'host': host,
                'port': 51820,
                'target_host': host,
                'raw': config_str
            }
        except:
            return None
    
    def is_ip_address(self, host):
        if not host:
            return False
        
        ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ipv4_pattern, host):
            parts = host.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        
        return False
    
    def is_domain(self, host):
        if not host:
            return False
        
        if self.is_ip_address(host):
            return False
        
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](\.[a-zA-Z]{2,})+$'
        if re.match(domain_pattern, host):
            return True
        
        if '.' in host and not self.is_ip_address(host):
            return True
        
        return False
    
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
        self.ipapi_cache = {}
        self.cache_file = 'geoip_cache.pkl'
        self.lock = threading.Lock()
        self.load_cache()
    
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
    
    def get_country_by_ipapi(self, ip):
        try:
            with self.lock:
                if ip in self.ipapi_cache:
                    return self.ipapi_cache[ip]
            
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,countryCode", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    country = data.get('countryCode', 'UNKNOWN')
                    with self.lock:
                        self.ipapi_cache[ip] = country
                    return country
        except Exception as e:
            logger.debug(f"IP-API failed for {ip}: {e}")
        
        return "UNKNOWN"
    
    def get_country(self, ip):
        return self.get_country_by_ipapi(ip)

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
            
            target_host = parsed.get('target_host', '')
            if not target_host:
                return None
            
            is_ip = self.parser.is_ip_address(target_host)
            
            if not is_ip:
                return {
                    'config': config_str,
                    'parsed': parsed,
                    'ip': None,
                    'country': 'DOMAIN',
                    'is_ip': False,
                    'target_host': target_host
                }
            
            country = self.geoip.get_country(target_host)
            
            return {
                'config': config_str,
                'parsed': parsed,
                'ip': target_host,
                'country': country,
                'is_ip': True,
                'target_host': target_host
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
