import re
import logging
from typing import List, Tuple

# Module imports
from modules.AttackDetector import AttackDetector
from modules.AttackPattern import AttackPattern
from modules.AttackType import AttackType

class RegexAttackDetector(AttackDetector):
    """Regular expression based attack detection."""

    def __init__(self):
        self.attack_patterns = self._initialize_patterns()
        self.logger = logging.getLogger(self.__class__.__name__)

    def _initialize_patterns(self) -> List[AttackPattern]:
        """Initialize attack patterns with their regex definitions."""
        return [
            AttackPattern(
                name="Shellshock",
                type=AttackType.SHELLSHOCK,
                patterns=[
                    r'\(\)\s*\{[^}]*\}',
                    r'echo\s+[^;]+;\s*/[^;]+',
                    r'env\s+x=\(\)\s*\{',
                    r'%28%29%7B%3A%3B%7D'
                ],
                confidence_weight=2.0
            ),
            AttackPattern(
                name="SQL Injection",
                type=AttackType.SQL_INJECTION,
                patterns=[
                    r"('\s*(OR|AND)\s*'?\d*'?\s*=\s*'?\d*)",
                    r'(UNION\s+(ALL\s+)?SELECT|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET)',
                    r'(SELECT\s+.*\s+FROM\s+information_schema)',
                    r"(--)|(#)|(/\*.*\*/)",
                    r'(SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\()',
                    r'(INTO\s+(OUT|DUMP)FILE)',
                    r'xp_cmdshell'
                ],
                confidence_weight=1.8
            ),
            AttackPattern(
                name="Command Injection",
                type=AttackType.COMMAND_INJECTION,
                patterns=[
                    r'[;&|]\s*(cat|ls|wget|curl|nc|bash|sh|cmd|powershell|python|perl|ruby)',
                    r'`[^`]+`',
                    r'\$\([^)]+\)',
                    r'\$\{[^}]+\}',
                    r'%0[aA]',
                    r'%26%26',
                    r'%7C%7C',
                    r'system\s*\(',
                    r'exec\s*\(',
                    r'eval\s*\('
                ],
                confidence_weight=1.9
            ),
            AttackPattern(
                name="Path Traversal",
                type=AttackType.PATH_TRAVERSAL,
                patterns=[
                    r'\.\.[\\/]',
                    r'%2e%2e[\\/]',
                    r'%252e%252e',
                    r'/etc/passwd',
                    r'/windows/win\.ini',
                    r'c:\\\\windows\\\\',
                    r'..%c0%af',
                    r'..%c1%9c'
                ],
                confidence_weight=1.5
            ),
            AttackPattern(
                name="Cross-Site Scripting",
                type=AttackType.XSS,
                patterns=[
                    r'<script[^>]*>',
                    r'javascript:',
                    r'onerror\s*=',
                    r'onload\s*=',
                    r'onclick\s*=',
                    r'<iframe[^>]*>',
                    r'<embed[^>]*>',
                    r'<object[^>]*>',
                    r'document\.(cookie|write|location)',
                    r'window\.(location|open)',
                    r'eval\s*\(',
                    r'expression\s*\('
                ],
                confidence_weight=1.6
            ),
            AttackPattern(
                name="Generic Exploit",
                type=AttackType.EXPLOIT,
                patterns=[
                    r'exploit',
                    r'payload',
                    r'overflow',
                    r'bypass',
                    r'0x[0-9a-fA-F]+',
                    r'\\x[0-9a-fA-F]{2}',
                    r'%[0-9a-fA-F]{2}',
                    r'AAAA{20,}'
                ],
                confidence_weight=1.2
            ),
            AttackPattern(
                name="Log4j/Log4Shell",
                type=AttackType.LOG4J,
                patterns=[
                    r'\$\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://',
                    r'\$\{jndi:',
                    r'\$\{\$\{::-j\}',
                    r'\$\{env:',
                    r'\$\{sys:',
                    r'\$\{java:',
                    r'\$\{lower:',
                    r'\$\{upper:',
                    r'\$\{::-',
                    r'%24%7Bjndi',
                    r'\${j\${::-n}di:',
                    r'%2524%257Bjndi'
                ],
                confidence_weight=2.5
            ),
            AttackPattern(
                name="LDAP Injection",
                type=AttackType.LDAP_INJECTION,
                patterns=[
                    r'\)\(\|',
                    r'\(\|.*\(.*=\*\)',
                    r'\)\(cn=\*',
                    r'\)\(uid=\*',
                    r'\)\(objectClass=\*',
                    r'\*\)\(&',
                    r'%29%28',
                    r'%2A%29%28'
                ],
                confidence_weight=1.7
            ),
            AttackPattern(
                name="XML External Entity",
                type=AttackType.XXE,
                patterns=[
                    r'<!ENTITY\s+\w+\s+SYSTEM',
                    r'<!DOCTYPE[^>]*\[',
                    r'<!ENTITY[^>]*>',
                    r'file://',
                    r'expect://',
                    r'php://filter',
                    r'data://text',
                    r'%3C!DOCTYPE',
                    r'%3C!ENTITY'
                ],
                confidence_weight=1.8
            ),
            AttackPattern(
                name="SSRF",
                type=AttackType.SSRF,
                patterns=[
                    r'(127\.0\.0\.1|localhost|0\.0\.0\.0)',
                    r'(169\.254\.169\.254)',
                    r'(metadata\.google\.internal)',
                    r'(169\.254\.170\.2)',
                    r'http[s]?://10\.',
                    r'http[s]?://172\.(1[6-9]|2[0-9]|3[0-1])\.',
                    r'http[s]?://192\.168\.',
                    r'@localhost',
                    r'@127\.0\.0\.1',
                    r'url=http'
                ],
                confidence_weight=1.6
            ),
            AttackPattern(
                name="Brute Force",
                type=AttackType.BRUTE_FORCE,
                patterns=[
                    r'authentication\s+fail',
                    r'invalid\s+(user|password|login|credentials)',
                    r'failed\s+(password|login|authentication)',
                    r'login\s+attempt',
                    r'access\s+denied',
                    r'incorrect\s+password',
                    r'too\s+many\s+(login|authentication)\s+attempts',
                    r'account\s+locked',
                    r'bad\s+password'
                ],
                confidence_weight=1.4
            ),
            AttackPattern(
                name="Port Scan",
                type=AttackType.PORT_SCAN,
                patterns=[
                    r'(nmap|masscan|zmap)',
                    r'SYN\s+scan',
                    r'port\s+scan',
                    r'connection\s+refused',
                    r'fin\s+scan',
                    r'xmas\s+scan',
                    r'null\s+scan',
                    r'udp\s+scan'
                ],
                confidence_weight=1.3
            ),
            AttackPattern(
                name="Reconnaissance",
                type=AttackType.RECONNAISSANCE,
                patterns=[
                    r'(nikto|whatweb|wpscan|dirbuster|gobuster|ffuf)',
                    r'robots\.txt',
                    r'\.git/config',
                    r'\.env',
                    r'\.htaccess',
                    r'wp-config\.php',
                    r'phpinfo\(\)',
                    r'server-status',
                    r'\.DS_Store'
                ],
                confidence_weight=1.2
            ),
            AttackPattern(
                name="Credential Access",
                type=AttackType.CREDENTIAL_ACCESS,
                patterns=[
                    r'password\s*=',
                    r'passwd\s*=',
                    r'credentials',
                    r'api[_-]?key',
                    r'secret[_-]?key',
                    r'access[_-]?token',
                    r'auth[_-]?token',
                    r'/etc/shadow',
                    r'mimikatz',
                    r'lsass'
                ],
                confidence_weight=1.5
            )
        ]

    def detect(self, log_data: str) -> Tuple[bool, AttackType, str]:
        """Detect attacks in log data using pattern matching."""
        if not log_data:
            return False, AttackType.UNKNOWN, ""

        detected_attacks = []

        for pattern in self.attack_patterns:
            if pattern.matches(log_data):
                # Extract the matching payload
                for regex in pattern.patterns:
                    match = re.search(regex, log_data, re.IGNORECASE)
                    if match:
                        payload = match.group(0)
                        detected_attacks.append((pattern.type, payload, pattern.confidence_weight))
                        break

        if detected_attacks:
            # Return the attack with highest confidence
            detected_attacks.sort(key=lambda x: x[2], reverse=True)
            attack_type, payload, _ = detected_attacks[0]
            return True, attack_type, payload

        return False, AttackType.UNKNOWN, ""
