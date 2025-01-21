import json
import os

class ConfigManager:
    def __init__(self):
        self.config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json')
        self.config = self.load_config()

    def load_config(self):
        """加载配置文件"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return {}

    def save_config(self, new_config):
        """保存配置文件"""
        try:
            # 合并配置
            self.config.update(new_config)
            # 保存到文件
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def get_value(self, key, default=None):
        """获取配置值"""
        return self.config.get(key, default)

    def get_config(self):
        """获取完整配置"""
        return self.config 