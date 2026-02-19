import os
import configparser

# ============================================================================
# Configuration Management for GUI
# ============================================================================

class ConfigManager:
    """Manages application configuration from config.ini file"""

    def __init__(self, config_file='config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_or_create_config()

    def load_or_create_config(self):
        """Load existing config or create default"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()

    def create_default_config(self):
        """Create default configuration file"""
        self.config['Elasticsearch'] = {
            'url': 'https://xxxxxxxxxx.io:9200',
            'username': 'xxxxxxxxxx',
            'password': 'xxxxxxxxxx',
            'verify_ssl': 'False',
            'timeout': '30'
        }

        self.config['Analysis'] = {
            'default_hours': '168',
            'min_severity': '15',
            'max_results': '10000',
            'batch_size': '100',
            'max_workers': '10'
        }

        self.config['UI'] = {
            'theme': 'dark',
            'refresh_interval': '30',
            'chart_style': 'cyberpunk',
            'enable_animations': 'True',
            'enable_sound_alerts': 'True'
        }

        self.config['Export'] = {
            'output_directory': './wazuh_analysis_output',
            'formats': 'csv,json,txt,agent_report',
            'include_visualizations': 'True'
        }

        self.config['GeoIP'] = {
            'enabled': 'False',
            'database_path': ''
        }

        self.config['ThreatIntel'] = {
            'virustotal_api_key': '',
            'abuseipdb_api_key': '',
            'otx_api_key': '',
            'cache_hours': '24'
        }

        self.config['O365Email'] = {
            'client_id': 'xxxxxxxxxx',
            'tenant_id': 'xxxxxxxxxx',
            'redirect_uri': 'http://localhost:8089/callback',
            'default_recipients': ''
        }

        self.config['GmailEmail'] = {
            'client_id': 'xxxxxxxxxx',
            'client_secret': 'xxxxxxxxxx',
            'redirect_uri': 'http://localhost:8089/callback',
            'default_recipients': ''
        }

        self.config['EmailNotifications'] = {
            'default_provider': 'O365',
            'skip_duplicate_findings': 'True',
            'always_send_critical': 'True',
            'always_send_minor': 'True',
            'attach_pdf': 'False',
            'attach_csv': 'False',
            'attach_excel': 'True',
            'attach_html': 'True'
        }

        self.config['Scheduling'] = {
            'auto_start_scheduler': 'False',
            'default_frequency': 'hourly',
            'default_time_range_hours': '24',
            'email_on_critical_only': 'False'
        }

        self.save_config()

    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            self.config.write(f)

    def get(self, section, key, fallback=None):
        """Get configuration value"""
        try:
            value = self.config.get(section, key)
            return value if value else fallback
        except (configparser.NoSectionError, configparser.NoOptionError, KeyError):
            return fallback

    def set(self, section, key, value):
        """Set configuration value"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = str(value)
        self.save_config()
