import asyncio
import socket
import ssl
import time
import ipaddress
import random
from urllib.parse import parse_qs, urlparse
from datetime import datetime

class SmartPingEngine:
    def __init__(self, timeout=4, max_latency=2500, max_concurrency=100):
        self.timeout = timeout
        self.max_latency = max_latency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.results_cache = {}
        self.stats = {
            'total_tested': 0,
            'passed': 0,
            'failed': 0,
            'timeout': 0,
            'high_latency': 0
        }
    
    async def tcp_ping(self, host, port):
        try:
            loop = asyncio.get_event_loop()
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)),
                timeout=self.timeout
            )
            latency = int((time.time() - start) * 1000)
            writer.close()
            await writer.wait_closed()
            return latency
        except asyncio.TimeoutError:
            self.stats['timeout'] += 1
            return None
        except Exception:
            return None
    
    async def tls_ping(self, host, port, sni=None):
        try:
            loop = asyncio.get_event_loop()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setblocking(False)
            wrapped_sock = context.wrap_socket(
                raw_sock, 
                server_hostname=sni or host, 
                do_handshake_on_connect=False
            )
            
            start = time.time()
            await loop.sock_connect(wrapped_sock, (host, int(port)))
            
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, wrapped_sock.do_handshake),
                    timeout=self.timeout
                )
            except asyncio.TimeoutError:
                wrapped_sock.close()
                self.stats['timeout'] += 1
                return None
            
            latency = int((time.time() - start) * 1000)
            wrapped_sock.close()
            return latency
        except Exception:
            return None
    
    def extract_server_info(self, config_str):
        parsed = {'original': config_str}
        
        try:
            if config_str.startswith('vmess://'):
                import base64
                import json
                base64_part = config_str[8:]
                if len(base64_part) % 4 != 0:
                    base64_part += '=' * (4 - len(base64_part) % 4)
                decoded = base64.b64decode(base64_part).decode('utf-8')
                vmess_data = json.loads(decoded)
                parsed['host'] = vmess_data.get('add', '')
                parsed['port'] = vmess_data.get('port', '443')
                parsed['type'] = 'vmess'
                parsed['tls'] = vmess_data.get('tls', '') == 'tls'
                return parsed
            
            elif config_str.startswith(('vless://', 'trojan://')):
                parsed_url = urlparse(config_str)
                parsed['host'] = parsed_url.hostname or ''
                parsed['port'] = str(parsed_url.port or 443)
                parsed['type'] = parsed_url.scheme
                
                params = parse_qs(parsed_url.query)
                parsed['tls'] = params.get('security', [''])[0] in ['tls', 'reality', 'xtls']
                parsed['sni'] = params.get('sni', [None])[0]
                return parsed
            
            elif config_str.startswith('ss://'):
                import base64
                parts = config_str.split('#', 1)[0]
                base_part = parts[5:]
                
                if '@' in base_part:
                    encoded_mp, server_part = base_part.split('@', 1)
                    if ':' in server_part:
                        server, port = server_part.split(':', 1)
                        parsed['host'] = server
                        parsed['port'] = port
                        parsed['type'] = 'ss'
                        return parsed
                return None
            
            elif config_str.startswith(('hysteria2://', 'hy2://', 'hysteria://', 'tuic://')):
                parsed_url = urlparse(config_str)
                parsed['host'] = parsed_url.hostname or ''
                parsed['port'] = str(parsed_url.port or 443)
                parsed['type'] = parsed_url.scheme
                return parsed
            
        except Exception:
            pass
        
        return None
    
    def is_valid_ip(self, host):
        try:
            ipaddress.ip_address(host)
            return True
        except:
            return False
    
    async def smart_ping(self, config_str):
        self.stats['total_tested'] += 1
        
        if config_str in self.results_cache:
            cache_time, latency = self.results_cache[config_str]
            if time.time() - cache_time < 300:
                return latency
        
        parsed = self.extract_server_info(config_str)
        if not parsed or not parsed.get('host'):
            self.stats['failed'] += 1
            return None
        
        host = parsed['host']
        port = parsed.get('port', '443')
        
        latency = None
        
        if parsed.get('type') in ['vless', 'trojan', 'vmess'] and parsed.get('tls', False):
            sni = parsed.get('sni') or host
            latency = await self.tls_ping(host, port, sni)
        else:
            latency = await self.tcp_ping(host, port)
        
        if latency is None:
            self.stats['failed'] += 1
            return None
        
        if latency > self.max_latency:
            self.stats['high_latency'] += 1
            return None
        
        self.stats['passed'] += 1
        self.results_cache[config_str] = (time.time(), latency)
        return latency
    
    async def batch_ping(self, configs, max_workers=50):
        self.semaphore = asyncio.Semaphore(max_workers)
        results = {}
        
        async def test_config(config):
            latency = await self.smart_ping(config)
            if latency is not None:
                results[config] = latency
        
        tasks = [test_config(config) for config in configs]
        await asyncio.gather(*tasks)
        
        return results
    
    def print_stats(self):
        print(f"\n📊 Ping Test Statistics:")
        print(f"   Total Tested: {self.stats['total_tested']}")
        print(f"   ✅ Passed: {self.stats['passed']}")
        print(f"   ❌ Failed: {self.stats['failed']}")
        print(f"   ⏱️  Timeout: {self.stats['timeout']}")
        print(f"   📈 High Latency (>={self.max_latency}ms): {self.stats['high_latency']}")
