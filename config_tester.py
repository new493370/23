import asyncio
import socket
import ssl
import time
import json
import hashlib
import base64
import uuid
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import os
from typing import Dict, List, Tuple, Optional, Any
import aiohttp
import dns.resolver

class SmartPingEngine:
    def __init__(self, timeout=4, max_latency=2500, max_concurrency=100):
        self.timeout = timeout
        self.max_latency = max_latency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.dns_cache = {}
        self.dns_semaphore = asyncio.Semaphore(20)

    async def resolve_dns(self, hostname: str) -> Optional[str]:
        if hostname in self.dns_cache:
            cached_time, cached_ip = self.dns_cache[hostname]
            if time.time() - cached_time < 300:
                return cached_ip
        
        async with self.dns_semaphore:
            try:
                loop = asyncio.get_event_loop()
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                
                answers = await loop.run_in_executor(
                    None, 
                    lambda: resolver.resolve(hostname, 'A')
                )
                
                if answers:
                    ip = str(answers[0])
                    self.dns_cache[hostname] = (time.time(), ip)
                    return ip
            except:
                return None
        return None

    async def tcp_ping(self, host: str, port: int) -> Optional[int]:
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            latency = int((time.time() - start) * 1000)
            writer.close()
            await writer.wait_closed()
            return latency
        except:
            return None

    async def tls_ping(self, host: str, port: int, sni: Optional[str] = None) -> Optional[int]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            loop = asyncio.get_event_loop()
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setblocking(False)
            
            wrapped_sock = context.wrap_socket(
                raw_sock, 
                server_hostname=sni or host,
                do_handshake_on_connect=False
            )

            start = time.time()
            await loop.sock_connect(wrapped_sock, (host, port))
            await loop.run_in_executor(None, wrapped_sock.do_handshake)
            latency = int((time.time() - start) * 1000)
            wrapped_sock.close()
            return latency
        except:
            return None

    async def http_ping(self, host: str, port: int, path: str = "/", tls: bool = False) -> Optional[int]:
        try:
            protocol = "https" if tls else "http"
            url = f"{protocol}://{host}:{port}{path}"
            
            start = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout, ssl=False) as response:
                    if response.status < 400:
                        latency = int((time.time() - start) * 1000)
                        return latency
            return None
        except:
            return None

    async def test_config(self, config_data: Dict[str, Any]) -> Tuple[bool, Optional[int], str]:
        config_str = config_data.get('raw', '')
        config_type = config_data.get('type', 'unknown')
        parsed = config_data.get('parsed', {})
        
        host = None
        port = None
        sni = None
        tls = False
        reality = False
        
        try:
            if config_type == 'vmess':
                host = parsed.get('add')
                port = int(parsed.get('port', 443))
                tls = parsed.get('tls', '') == 'tls'
                sni = parsed.get('sni', host)
                
            elif config_type == 'vless':
                host = parsed.get('host') or parsed.get('add')
                port = int(parsed.get('port', 443))
                params = parsed.get('params', {})
                tls = params.get('tls') == 'tls' or params.get('security') == 'tls'
                reality = params.get('security') == 'reality'
                sni = params.get('sni') or params.get('host') or host
                
            elif config_type == 'trojan':
                host = parsed.get('host') or parsed.get('add')
                port = int(parsed.get('port', 443))
                params = parsed.get('params', {})
                tls = True
                sni = params.get('sni') or params.get('peer') or host
                
            elif config_type == 'ss':
                host = parsed.get('host') or parsed.get('server')
                port = int(parsed.get('port', 443))
                tls = False
                
            elif config_type in ['hysteria2', 'hy2', 'hysteria']:
                host = parsed.get('host') or parsed.get('server')
                port = int(parsed.get('port', 443))
                tls = True
                sni = parsed.get('sni') or host
                
            elif config_type == 'tuic':
                host = parsed.get('host') or parsed.get('server')
                port = int(parsed.get('port', 443))
                tls = True
                sni = parsed.get('sni') or host
                
            if not host or not port:
                return False, None, f"Invalid host/port: {host}:{port}"
            
            ip = await self.resolve_dns(host)
            if not ip:
                return False, None, f"DNS resolution failed: {host}"
            
            async with self.semaphore:
                tcp_latency = await self.tcp_ping(ip, port)
                if tcp_latency is None:
                    return False, None, f"TCP connection failed: {host}:{port}"
                
                if tls or reality:
                    tls_latency = await self.tls_ping(ip, port, sni)
                    if tls_latency is None:
                        return False, tcp_latency, f"TLS handshake failed: {host}:{port}"
                    latency = tls_latency
                else:
                    latency = tcp_latency
                
                if latency > self.max_latency:
                    return False, latency, f"High latency: {latency}ms > {self.max_latency}ms"
                
                return True, latency, f"OK - {latency}ms"
                
        except Exception as e:
            return False, None, f"Test error: {str(e)}"

class ConfigTester:
    def __init__(self):
        self.engine = SmartPingEngine(timeout=4, max_latency=2500, max_concurrency=100)
        self.results = {
            'passed': [],
            'failed': [],
            'stats': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'by_type': {}
            }
        }
        
    def parse_config(self, config_str: str) -> Dict[str, Any]:
        result = {
            'raw': config_str,
            'type': 'unknown',
            'parsed': {}
        }
        
        try:
            if config_str.startswith('vmess://'):
                result['type'] = 'vmess'
                try:
                    base64_part = config_str[8:]
                    if len(base64_part) % 4 != 0:
                        base64_part += '=' * (4 - len(base64_part) % 4)
                    decoded = base64.b64decode(base64_part).decode('utf-8')
                    parsed = json.loads(decoded)
                    result['parsed'] = parsed
                except:
                    pass
                    
            elif config_str.startswith('vless://'):
                result['type'] = 'vless'
                try:
                    parsed = urlparse(config_str)
                    host_port = parsed.netloc.split('@')
                    if len(host_port) > 1:
                        host, port = host_port[1].split(':') if ':' in host_port[1] else (host_port[1], '443')
                        result['parsed'] = {
                            'host': host,
                            'port': port,
                            'params': dict(parse_qs(parsed.query))
                        }
                except:
                    pass
                    
            elif config_str.startswith('trojan://'):
                result['type'] = 'trojan'
                try:
                    parsed = urlparse(config_str)
                    host_port = parsed.netloc.split('@')
                    if len(host_port) > 1:
                        host, port = host_port[1].split(':') if ':' in host_port[1] else (host_port[1], '443')
                        result['parsed'] = {
                            'host': host,
                            'port': port,
                            'params': dict(parse_qs(parsed.query))
                        }
                except:
                    pass
                    
            elif config_str.startswith('ss://'):
                result['type'] = 'ss'
                try:
                    parts = config_str[5:].split('#', 1)
                    base_part = parts[0]
                    
                    if '@' in base_part:
                        method_pass, host_port = base_part.split('@', 1)
                        if ':' in host_port:
                            host, port = host_port.split(':', 1)
                            result['parsed'] = {
                                'host': host,
                                'port': port
                            }
                except:
                    pass
                    
            elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://'):
                result['type'] = 'hysteria2'
                try:
                    parsed = urlparse(config_str)
                    host_port = parsed.netloc.split('@')
                    if len(host_port) > 1:
                        host, port = host_port[1].split(':') if ':' in host_port[1] else (host_port[1], '443')
                        result['parsed'] = {
                            'host': host,
                            'port': port,
                            'params': dict(parse_qs(parsed.query))
                        }
                except:
                    pass
                    
            elif config_str.startswith('tuic://'):
                result['type'] = 'tuic'
                try:
                    parsed = urlparse(config_str)
                    host_port = parsed.netloc.split('@')
                    if len(host_port) > 1:
                        host, port = host_port[1].split(':') if ':' in host_port[1] else (host_port[1], '443')
                        result['parsed'] = {
                            'host': host,
                            'port': port,
                            'params': dict(parse_qs(parsed.query))
                        }
                except:
                    pass
                    
        except Exception as e:
            print(f"Parse error: {e}")
            
        return result
    
    def read_configs_from_file(self, filepath: str) -> List[str]:
        configs = []
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            configs.append(line)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        return configs
    
    async def test_configs_batch(self, configs: List[str], source: str = "unknown") -> Tuple[List[str], List[str]]:
        passed = []
        failed = []
        
        print(f"\nTesting {len(configs)} configs from {source}...")
        
        tasks = []
        parsed_configs = []
        
        for config_str in configs:
            parsed = self.parse_config(config_str)
            if parsed['type'] != 'unknown':
                parsed_configs.append(parsed)
        
        self.results['stats']['total'] += len(parsed_configs)
        
        for i, parsed in enumerate(parsed_configs, 1):
            if i % 100 == 0:
                print(f"  Progress: {i}/{len(parsed_configs)}")
            
            is_alive, latency, message = await self.engine.test_config(parsed)
            
            if is_alive:
                passed.append(parsed['raw'])
                self.results['stats']['passed'] += 1
                
                if parsed['type'] not in self.results['stats']['by_type']:
                    self.results['stats']['by_type'][parsed['type']] = {'passed': 0, 'failed': 0}
                self.results['stats']['by_type'][parsed['type']]['passed'] += 1
            else:
                failed.append(parsed['raw'])
                self.results['stats']['failed'] += 1
                
                if parsed['type'] not in self.results['stats']['by_type']:
                    self.results['stats']['by_type'][parsed['type']] = {'passed': 0, 'failed': 0}
                self.results['stats']['by_type'][parsed['type']]['failed'] += 1
        
        return passed, failed
    
    def save_results(self, passed_configs: List[str], source: str):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        os.makedirs('configs/tested', exist_ok=True)
        
        filename = f"configs/tested/{source}_tested.txt"
        content = f"# Tested {source.upper()} Configurations\n"
        content += f"# Updated: {timestamp}\n"
        content += f"# Total Tested: {len(passed_configs)}\n"
        content += f"# Max Latency: {self.engine.max_latency}ms\n\n"
        content += "\n".join(passed_configs)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        
        report = f"configs/tested/test_report.txt"
        report_content = f"# TEST REPORT - {timestamp}\n"
        report_content += f"{'='*50}\n"
        report_content += f"Total Configs Tested: {self.results['stats']['total']}\n"
        report_content += f"Passed: {self.results['stats']['passed']}\n"
        report_content += f"Failed: {self.results['stats']['failed']}\n"
        report_content += f"Success Rate: {(self.results['stats']['passed']/self.results['stats']['total']*100):.1f}%\n"
        report_content += f"\nBy Protocol:\n"
        
        for proto, stats in self.results['stats']['by_type'].items():
            total = stats['passed'] + stats['failed']
            rate = (stats['passed']/total*100) if total > 0 else 0
            report_content += f"  {proto}: {stats['passed']}/{total} ({rate:.1f}%)\n"
        
        with open(report, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return len(passed_configs)

async def main():
    print("=" * 60)
    print("ARISTA CONFIG TESTER v1.0")
    print("=" * 60)
    
    tester = ConfigTester()
    
    telegram_configs = tester.read_configs_from_file('configs/telegram/all.txt')
    telegram_passed, telegram_failed = await tester.test_configs_batch(telegram_configs, "telegram")
    tester.save_results(telegram_passed, "telegram")
    
    github_configs = tester.read_configs_from_file('configs/github/all.txt')
    github_passed, github_failed = await tester.test_configs_batch(github_configs, "github")
    tester.save_results(github_passed, "github")
    
    all_passed = telegram_passed + github_passed
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('configs/tested/all_tested.txt', 'w', encoding='utf-8') as f:
        f.write(f"# All Tested Configurations\n")
        f.write(f"# Updated: {timestamp}\n")
        f.write(f"# Total: {len(all_passed)}\n")
        f.write(f"# Telegram Passed: {len(telegram_passed)}\n")
        f.write(f"# GitHub Passed: {len(github_passed)}\n\n")
        f.write("\n".join(all_passed))
    
    print("\n" + "=" * 60)
    print("TESTING COMPLETE")
    print("=" * 60)
    print(f"Telegram: {len(telegram_passed)}/{len(telegram_configs)} passed")
    print(f"GitHub: {len(github_passed)}/{len(github_configs)} passed")
    print(f"Total: {len(all_passed)}/{len(telegram_configs) + len(github_configs)} passed")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
