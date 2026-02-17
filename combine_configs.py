import os
import hashlib
from datetime import datetime

class ConfigCombiner:
    def __init__(self):
        self.categories = [
            'vmess', 'vless', 'trojan', 'ss',
            'hysteria2', 'hysteria', 'tuic', 
            'wireguard', 'other'
        ]
    
    def read_configs(self, filepath):
        if not os.path.exists(filepath):
            return []
        
        configs = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        configs.append(line)
        except:
            pass
        
        return configs
    
    def categorize_configs(self, configs):
        categories = {cat: [] for cat in self.categories}
        
        for config in configs:
            if config.startswith('vmess://'):
                categories['vmess'].append(config)
            elif config.startswith('vless://'):
                categories['vless'].append(config)
            elif config.startswith('trojan://'):
                categories['trojan'].append(config)
            elif config.startswith('ss://'):
                categories['ss'].append(config)
            elif config.startswith('hysteria2://') or config.startswith('hy2://'):
                categories['hysteria2'].append(config)
            elif config.startswith('hysteria://'):
                categories['hysteria'].append(config)
            elif config.startswith('tuic://'):
                categories['tuic'].append(config)
            elif config.startswith('wireguard://'):
                categories['wireguard'].append(config)
            else:
                categories['other'].append(config)
        
        return categories
    
    def deduplicate(self, configs):
        unique_configs = []
        seen_hashes = set()
        
        for config in configs:
            config_hash = hashlib.md5(config.encode()).hexdigest()
            if config_hash not in seen_hashes:
                seen_hashes.add(config_hash)
                unique_configs.append(config)
        
        return unique_configs
    
    def combine(self):
        os.makedirs('configs/combined', exist_ok=True)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        tested_telegram = self.read_configs('configs/tested/telegram_tested.txt')
        tested_github = self.read_configs('configs/tested/github_tested.txt')
        all_tested = self.read_configs('configs/tested/all_tested.txt')
        
        categorized = self.categorize_configs(all_tested)
        
        for category, configs in categorized.items():
            if configs:
                unique_configs = self.deduplicate(configs)
                filename = f"configs/combined/{category}.txt"
                content = f"# Combined {category.upper()} Configurations (Tested)\n"
                content += f"# Updated: {timestamp}\n"
                content += f"# Count: {len(unique_configs)}\n"
                content += f"# Sources: Telegram ({len([c for c in unique_configs if c in tested_telegram])}) + "
                content += f"GitHub ({len([c for c in unique_configs if c in tested_github])})\n\n"
                content += "\n".join(unique_configs)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
        
        if all_tested:
            filename = "configs/combined/all.txt"
            content = f"# All Combined Configurations (Tested)\n"
            content += f"# Updated: {timestamp}\n"
            content += f"# Total Count: {len(all_tested)}\n"
            content += f"# Sources: Telegram ({len(tested_telegram)}) + GitHub ({len(tested_github)})\n\n"
            content += "\n".join(all_tested)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
        
        print("=" * 60)
        print("CONFIG COMBINER - TESTED CONFIGS")
        print("=" * 60)
        print(f"Tested Telegram configs: {len(tested_telegram)}")
        print(f"Tested GitHub configs: {len(tested_github)}")
        print(f"Total tested configs: {len(all_tested)}")
        print("\n📁 Files created in configs/combined/:")
        
        for category in self.categories:
            if os.path.exists(f'configs/combined/{category}.txt'):
                with open(f'configs/combined/{category}.txt', 'r', encoding='utf-8') as f:
                    lines = [line for line in f if line.strip() and not line.startswith('#')]
                print(f"  {category}.txt: {len(lines)} configs")
        
        print(f"  all.txt: {len(all_tested)} configs")
        print("=" * 60)

def main():
    combiner = ConfigCombiner()
    combiner.combine()

if __name__ == "__main__":
    main()
