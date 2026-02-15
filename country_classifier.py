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
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64

try:
    import geoip2.database
    import geoip2.types
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

try:
    import pyasn
    ASN_AVAILABLE = True
except ImportError:
    ASN_AVAILABLE = False

class ASNBasedCountryDetector:
    def __init__(self):
        self.asn_db = None
        self.asn_cache = {}
        self.cache_file = "configs/country/asn_cache.json"
        self.iranian_asns = {
            12880, 16276, 20506, 24550, 24631, 24761, 25184, 31549, 34224, 34475,
            35986, 39501, 39626, 39737, 39913, 41218, 41750, 41893, 41954, 42186,
            42227, 42337, 42645, 42764, 42826, 42866, 42994, 43234, 43304, 43421,
            43455, 43532, 43628, 43736, 43754, 43762, 43783, 43819, 43838, 43873,
            43936, 43994, 44037, 44134, 44217, 44244, 44266, 44313, 44331, 44350,
            44396, 44417, 44433, 44447, 44457, 44467, 44479, 44486, 44493, 44506,
            44510, 44514, 44518, 44522, 44525, 44528, 44531, 44534, 44537, 44540,
            44543, 44546, 44549, 44552, 44555, 44558, 44561, 44564, 44567, 44570,
            44573, 44576, 44579, 44582, 44585, 44588, 44591, 44594, 44597, 44600,
            44603, 44606, 44609, 44612, 44615, 44618, 44621, 44624, 44627, 44630,
            57218, 57256, 57276, 57311, 57325, 57345, 57369, 57388, 57413, 57435,
            57452, 57468, 57484, 57502, 57518, 57533, 57549, 57564, 57579, 57594,
            57609, 57624, 57639, 57654, 57669, 57684, 57699, 57714, 57729, 57744,
            57759, 57774, 57789, 57804, 57819, 57834, 57849, 57864, 57879, 57894,
            57909, 57924, 57939, 57954, 57969, 57984, 57999, 58014, 58029, 58044,
            58059, 58074, 58089, 58104, 58119, 58134, 58149, 58164, 58179, 58194,
            58209, 58224, 58239, 58254, 58269, 58284, 58299, 58314, 58329, 58344,
            58359, 58374, 58389, 58404, 58419, 58434, 58449, 58464, 58479, 58494,
            58509, 58524, 58539, 58554, 58569, 58584, 58599, 58614, 58629, 58644,
            58659, 58674, 58689, 58704, 58719, 58734, 58749, 58764, 58779, 58794,
            58809, 58824, 58839, 58854, 58869, 58884, 58899, 58914, 58929, 58944,
            58959, 58974, 58989, 59004, 59019, 59034, 59049, 59064, 59079, 59094,
            59109, 59124, 59139, 59154, 59169, 59184, 59199, 59214, 59229, 59244,
            59259, 59274, 59289, 59304, 59319, 59334, 59349, 59364, 59379, 59394,
            59409, 59424, 59439, 59454, 59469, 59484, 59499, 59514, 59529, 59544,
            59559, 59574, 59589, 59604, 59619, 59634, 59649, 59664, 59679, 59694,
            59709, 59724, 59739, 59754, 59769, 59784, 59799, 59814, 59829, 59844,
            59859, 59874, 59889, 59904, 59919, 59934, 59949, 59964, 59979, 59994,
            60009, 60024, 60039, 60054, 60069, 60084, 60099, 60114, 60129, 60144,
            60159, 60174, 60189, 60204, 60219, 60234, 60249, 60264, 60279, 60294,
            60309, 60324, 60339, 60354, 60369, 60384, 60399, 60414, 60429, 60444,
            60459, 60474, 60489, 60504, 60519, 60534, 60549, 60564, 60579, 60594,
            60609, 60624, 60639, 60654, 60669, 60684, 60699, 60714, 60729, 60744,
            60759, 60774, 60789, 60804, 60819, 60834, 60849, 60864, 60879, 60894,
            60909, 60924, 60939, 60954, 60969, 60984, 60999, 61014, 61029, 61044,
            61059, 61074, 61089, 61104, 61119, 61134, 61149, 61164, 61179, 61194,
            61209, 61224, 61239, 61254, 61269, 61284, 61299, 61314, 61329, 61344,
            61359, 61374, 61389, 61404, 61419, 61434, 61449, 61464, 61479, 61494,
            61509, 61524, 61539, 61554, 61569, 61584, 61599, 61614, 61629, 61644,
            61659, 61674, 61689, 61704, 61719, 61734, 61749, 61764, 61779, 61794,
            61809, 61824, 61839, 61854, 61869, 61884, 61899, 61914, 61929, 61944,
            61959, 61974, 61989, 62004, 62019, 62034, 62049, 62064, 62079, 62094,
            62109, 62124, 62139, 62154, 62169, 62184, 62199, 62214, 62229, 62244,
            62259, 62274, 62289, 62304, 62319, 62334, 62349, 62364, 62379, 62394,
            62409, 62424, 62439, 62454, 62469, 62484, 62499, 62514, 62529, 62544,
            62559, 62574, 62589, 62604, 62619, 62634, 62649, 62664, 62679, 62694,
            62709, 62724, 62739, 62754, 62769, 62784, 62799, 62814, 62829, 62844,
            62859, 62874, 62889, 62904, 62919, 62934, 62949, 62964, 62979, 62994,
            63009, 63024, 63039, 63054, 63069, 63084, 63099, 63114, 63129, 63144,
            63159, 63174, 63189, 63204, 63219, 63234, 63249, 63264, 63279, 63294,
            63309, 63324, 63339, 63354, 63369, 63384, 63399, 63414, 63429, 63444,
            63459, 63474, 63489, 63504, 63519, 63534, 63549, 63564, 63579, 63594,
            63609, 63624, 63639, 63654, 63669, 63684, 63699, 63714, 63729, 63744,
            63759, 63774, 63789, 63804, 63819, 63834, 63849, 63864, 63879, 63894,
            63909, 63924, 63939, 63954, 63969, 63984, 63999
        }
        self.init_asn_db()
        self.load_cache()
    
    def init_asn_db(self):
        if not ASN_AVAILABLE:
            return
        
        asn_dat_paths = [
            "geoip/ipasn.dat",
            "ipasn.dat",
            "/usr/share/ipasn/ipasn.dat"
        ]
        
        for path in asn_dat_paths:
            if os.path.exists(path):
                try:
                    self.asn_db = pyasn.pyasn(path)
                    break
                except:
                    continue
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    for ip, data in cache_data.items():
                        try:
                            timestamp = datetime.fromisoformat(data['timestamp'])
                            if datetime.now() - timestamp < timedelta(days=7):
                                self.asn_cache[ip] = {
                                    'asn': data.get('asn'),
                                    'country': data.get('country')
                                }
                        except:
                            continue
        except:
            pass
    
    def save_cache(self):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            cache_data = {}
            
            for ip, data in self.asn_cache.items():
                cache_data[ip] = {
                    'asn': data.get('asn'),
                    'country': data.get('country'),
                    'timestamp': datetime.now().isoformat()
                }
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
        except:
            pass
    
    def get_asn_for_ip(self, ip):
        if ip in self.asn_cache:
            return self.asn_cache[ip].get('asn')
        
        if not self.asn_db:
            return None
        
        try:
            asn = self.asn_db.lookup(ip)
            if asn and asn[0]:
                self.asn_cache[ip] = {'asn': asn[0]}
                return asn[0]
            return None
        except:
            return None
    
    def get_real_country_by_asn(self, ip):
        if ip in self.asn_cache and 'country' in self.asn_cache[ip]:
            return self.asn_cache[ip]['country']
        
        asn = self.get_asn_for_ip(ip)
        if asn and asn in self.iranian_asns:
            self.asn_cache[ip] = {'asn': asn, 'country': 'IR'}
            return 'IR'
        
        if asn:
            self.asn_cache[ip] = {'asn': asn, 'country': 'XX'}
            return 'XX'
        
        return None

class AristaRealGeoEngine:
    def __init__(self, classifier):
        self.classifier = classifier
        self.asn_detector = ASNBasedCountryDetector()

    def extract_real_targets(self, parsed):
        targets = []
        
        if not parsed:
            return targets
        
        d = parsed.get('dict', {}) if isinstance(parsed, dict) else {}
        
        for key in ['sni', 'host', 'authority']:
            val = d.get(key)
            if val and isinstance(val, str):
                val = val.strip()
                if val and not self.classifier.is_cdn_domain(val):
                    targets.append(val)
        
        original = parsed.get('original', '')
        if original and isinstance(original, str):
            for param in ['sni=', 'host=', 'authority=']:
                if param in original:
                    try:
                        parts = original.split(param, 1)
                        if len(parts) > 1:
                            part = parts[1]
                            host = part.split('&', 1)[0].split('#', 1)[0].split('/')[0].strip()
                            if host and not self.classifier.is_cdn_domain(host):
                                targets.append(host)
                    except:
                        pass
        
        return list(dict.fromkeys(targets))

    def get_real_country(self, parsed):
        if not parsed:
            return 'XX'
        
        targets = self.extract_real_targets(parsed)
        
        for target in targets:
            country = self.classifier.get_country_for_host(target)
            if country and country != 'XX':
                return country
        
        ip = self.get_real_server_ip(parsed)
        if ip:
            asn_country = self.asn_detector.get_real_country_by_asn(ip)
            if asn_country and asn_country != 'XX':
                return asn_country
        
        if ip:
            return self.classifier.get_country_from_ip(ip)
        
        return 'XX'

    def get_real_server_ip(self, parsed):
        if not parsed:
            return None
        
        if parsed.get('type') == 'vmess':
            ip = parsed.get('dict', {}).get('add', '')
            if self.classifier.is_valid_ip(ip):
                return ip
        else:
            ip = parsed.get('host', '')
            if self.classifier.is_valid_ip(ip):
                return ip
        
        host = parsed.get('host', '')
        if host and not self.classifier.is_valid_ip(host):
            ips = self.classifier.resolve_domain(host)
            if ips:
                return ips[0]
        
        return None

class RealServerDetector:
    def __init__(self, classifier):
        self.classifier = classifier

    def extract_real_host(self, parsed):
        if not parsed or 'host' not in parsed:
            return None

        host = parsed['host'].strip()

        if self.classifier.is_valid_ip(host):
            return host

        return host

    def get_real_server_ip(self, parsed):
        host = self.extract_real_host(parsed)
        if not host:
            return None

        if self.classifier.is_valid_ip(host):
            return host

        ips = self.classifier.resolve_domain(host)
        if ips:
            return ips[0]

        return None

    def get_real_country(self, parsed):
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
        self.load_cache()
        self.init_geoip()
        self.real_detector = AristaRealGeoEngine(self)
        
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
            'bootstrapcdn.com', 'cloudflare-ipfs.com'
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
        if not domain or not isinstance(domain, str):
            return False
        domain_lower = domain.lower()
        for cdn in self.cdn_domains:
            if cdn in domain_lower or domain_lower.endswith('.' + cdn):
                return True
        return False
    
    def extract_domain(self, host):
        if not host or not isinstance(host, str):
            return ''
        
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
        if not domain or not isinstance(domain, str):
            return []
        
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
            
            self.dns_cache[domain] = ips[:3]
            return ips[:3]
        except:
            self.dns_cache[domain] = []
            return []
    
    def get_country_from_ip(self, ip):
        if not self.geoip_reader:
            return 'XX'
        
        if ip in self.ip_country_cache:
            return self.ip_country_cache[ip]
        
        try:
            response = self.geoip_reader.country(ip)
            if response.country.iso_code:
                country = response.country.iso_code
                self.ip_country_cache[ip] = country
                return country
            return 'XX'
        except:
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
            
            if '@' in without_proto:
                uuid_part, rest = without_proto.split('@', 1)
                
                if '?' in rest:
                    host_port, params = rest.split('?', 1)
                else:
                    host_port, params = rest, ''
                
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                    port = port.split('/')[0].split('#')[0]
                else:
                    host, port = host_port, '443'
                
                return {
                    'type': 'vless',
                    'host': host,
                    'port': port,
                    'original': config_str,
                    'dict': dict(parse_qs(params)) if params else {}
                }
            else:
                return None
        except Exception as e:
            return None
    
    def parse_trojan_config(self, config_str):
        try:
            if not config_str.startswith('trojan://'):
                return None
            
            without_proto = config_str[9:]
            
            if '@' in without_proto:
                password, rest = without_proto.split('@', 1)
                
                if '?' in rest:
                    host_port, params = rest.split('?', 1)
                else:
                    host_port, params = rest, ''
                
                if ':' in host_port:
                    host, port = host_port.split(':', 1)
                    port = port.split('/')[0].split('#')[0]
                else:
                    host, port = host_port, '443'
                
                return {
                    'type': 'trojan',
                    'host': host,
                    'port': port,
                    'original': config_str,
                    'dict': dict(parse_qs(params)) if params else {}
                }
            return None
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
                    params = {}
                    
                    if '?' in without_proto:
                        without_proto, param_str = without_proto.split('?', 1)
                        params = dict(parse_qs(param_str))
                    
                    if '@' in without_proto:
                        parts = without_proto.split('@', 1)
                        if len(parts) == 2:
                            server_part = parts[1].split('#')[0].split('/')[0]
                            if ':' in server_part:
                                host = server_part.split(':')[0]
                                port = server_part.split(':')[1]
                            else:
                                host = server_part
                    else:
                        server_part = without_proto.split('#')[0].split('/')[0]
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
                            'original': config_str,
                            'dict': params
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
        
        with ThreadPoolExecutor(max_workers=10) as executor:
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
                    parsed, country = future.result()
                    if parsed and country:
                        if country == 'CDN':
                            cdn_skipped += 1
                            continue
                        
                        if country not in results:
                            results[country] = []
                        results[country].append(config)
                    else:
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
            if country in ['CDN', 'XX']:
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
    print("🌍 COUNTRY CLASSIFIER - REAL SERVER DETECTION (FIXED VERSION)")
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
    
    real_countries = [c for c in country_results.keys() if c not in ['CDN', 'XX']]
    print(f"  Unique countries: {len(real_countries)}")
    
    if real_countries:
        country_count, total_saved = classifier.save_country_files(
            country_results, total_processed, total_failed, total_cdn_skipped
        )
        print(f"\n✅ Saved configurations for {country_count} countries")
        print(f"  Total configs by country: {total_saved}")
    
    classifier.save_cache()
    
    top_countries = sorted(
        [(c, len(configs)) for c, configs in country_results.items() 
         if c not in ['CDN', 'XX']],
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
