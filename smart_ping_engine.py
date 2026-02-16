#!/usr/bin/env python3
import asyncio
import socket
import ssl
import time
import ipaddress
import random
import json
import base64
import os
import sys
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

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
        except asyncio.TimeoutError:
            self.stats['timeout'] += 1
            return None
        except Exception:
            return None
    
    async def tls_ping(self, host: str, port: int, sni: Optional[str] = None) -> Optional[int]:
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
            await loop.sock_connect(wrapped_sock, (host, port))
            
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
    
    def extract_server_info(self, config_str: str) -> Optional[Dict[str, Any]]:
        parsed = {'original': config_str}
        
        try:
            if config_str.startswith('vmess://'):
                base64_part = config_str[8:]
                if len(base64_part) % 4 != 0:
                    base64_part += '=' * (4 - len(base64_part) % 4)
                decoded = base64.b64decode(base64_part).decode('utf-8')
                vmess_data = json.loads(decoded)
                parsed['host'] = vmess_data.get('add', '')
                parsed['port'] = int(vmess_data.get('port', 443))
                parsed['type'] = 'vmess'
                parsed['tls'] = vmess_data.get('tls', '') == 'tls'
                return parsed
            
            elif config_str.startswith(('vless://', 'trojan://')):
                parsed_url = urlparse(config_str)
                parsed['host'] = parsed_url.hostname or ''
                parsed['port'] = parsed_url.port or 443
                parsed['type'] = parsed_url.scheme
                
                params = parse_qs(parsed_url.query)
                parsed['tls'] = params.get('security', [''])[0] in ['tls', 'reality', 'xtls']
                parsed['sni'] = params.get('sni', [None])[0]
                return parsed
            
            elif config_str.startswith('ss://'):
                parts = config_str.split('#', 1)[0]
                base_part = parts[5:]
                
                if '@' in base_part:
                    encoded_mp, server_part = base_part.split('@', 1)
                    if ':' in server_part:
                        server, port = server_part.split(':', 1)
                        parsed['host'] = server
                        parsed['port'] = int(port)
                        parsed['type'] = 'ss'
                        return parsed
                return None
            
            elif config_str.startswith(('hysteria2://', 'hy2://', 'hysteria://', 'tuic://')):
                parsed_url = urlparse(config_str)
                parsed['host'] = parsed_url.hostname or ''
                parsed['port'] = parsed_url.port or 443
                parsed['type'] = parsed_url.scheme
                return parsed
            
        except Exception as e:
            pass
        
        return None
    
    async def smart_ping(self, config_str: str) -> Optional[int]:
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
        port = parsed.get('port', 443)
        
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
    
    async def batch_ping(self, configs: List[str], max_workers: int = 50) -> Dict[str, int]:
        self.semaphore = asyncio.Semaphore(max_workers)
        results = {}
        
        async def test_config(config: str):
            try:
                async with self.semaphore:
                    latency = await self.smart_ping(config)
                    if latency is not None:
                        results[config] = latency
            except Exception as e:
                pass
        
        tasks = [test_config(config) for config in configs]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    def print_stats(self):
        print(f"\n Ping Test Statistics:")
        print(f"   Total Tested: {self.stats['total_tested']}")
        print(f"   Passed: {self.stats['passed']}")
        print(f"   Failed: {self.stats['failed']}")
        print(f"   Timeout: {self.stats['timeout']}")
        print(f"   High Latency (>={self.max_latency}ms): {self.stats['high_latency']}")

async def main_async():
    print("=" * 60)
    print("ARISTA SMART PING ENGINE")
    print("=" * 60)
    
    engine = SmartPingEngine(timeout=4, max_latency=2500)
    
    all_configs = []
    
    telegram_file = "configs/telegram/all.txt"
    github_file = "configs/github/all.txt"
    
    if os.path.exists(telegram_file):
        with open(telegram_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    all_configs.append(line)
    
    if os.path.exists(github_file):
        with open(github_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    all_configs.append(line)
    
    if not all_configs:
        print(" No configs found to test")
        return
    
    print(f" Testing {len(all_configs)} configs...")
    
    batch_size = 200
    working_configs = []
    
    for i in range(0, len(all_configs), batch_size):
        batch = all_configs[i:i+batch_size]
        print(f"\n Testing batch {i//batch_size + 1}/{(len(all_configs)-1)//batch_size + 1} ({len(batch)} configs)")
        
        try:
            results = await engine.batch_ping(batch, max_workers=30)
            working_configs.extend(results.keys())
        except Exception as e:
            print(f"  Error in batch: {e}")
        
        engine.print_stats()
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    categories = {
        'vmess': [], 'vless': [], 'trojan': [], 'ss': [],
        'hysteria2': [], 'hysteria': [], 'tuic': [], 'other': []
    }
    
    for config in working_configs:
        if config.startswith('vmess://'):
            categories['vmess'].append(config)
        elif config.startswith('vless://'):
            categories['vless'].append(config)
        elif config.startswith('trojan://'):
            categories['trojan'].append(config)
        elif config.startswith('ss://'):
            categories['ss'].append(config)
        elif config.startswith(('hysteria2://', 'hy2://')):
            categories['hysteria2'].append(config)
        elif config.startswith('hysteria://'):
            categories['hysteria'].append(config)
        elif config.startswith('tuic://'):
            categories['tuic'].append(config)
        else:
            categories['other'].append(config)
    
    os.makedirs('configs/temp', exist_ok=True)
    
    for category, configs in categories.items():
        if configs:
            filename = f"configs/temp/{category}.txt"
            content = f"# Tested Working {category.upper()} Configurations\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Count: {len(configs)}\n"
            content += f"# Average Latency: Working\n\n"
            content += "\n".join(configs)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
    
    all_working_file = "configs/temp/all_working.txt"
    with open(all_working_file, 'w', encoding='utf-8') as f:
        content = f"# All Working Configurations\n"
        content += f"# Updated: {timestamp}\n"
        content += f"# Count: {len(working_configs)}\n"
        content += f"# Test Results: {engine.stats['passed']} working / {engine.stats['total_tested']} tested\n\n"
        content += "\n".join(working_configs)
        f.write(content)
    
    print(f"\n Testing complete!")
    print(f" Working configs saved to configs/temp/")
    print(f"   Total working: {len(working_configs)}")

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n\n Process interrupted by user")
    except Exception as e:
        print(f"\n Error: {e}")

if __name__ == "__main__":
    main()
