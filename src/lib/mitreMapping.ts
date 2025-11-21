// MITRE ATT&CK Technique Mapping for Security Vulnerabilities

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
}

export const MITRE_MAPPINGS: Record<string, MitreTechnique> = {
  'exposed-api-key': {
    id: 'T1552',
    name: 'Unsecured Credentials',
    tactic: 'Credential Access',
    description: 'Adversaries may search compromised systems to find and obtain insecurely stored credentials.',
    url: 'https://attack.mitre.org/techniques/T1552/'
  },
  'exposed-env-file': {
    id: 'T1552.001',
    name: 'Credentials In Files',
    tactic: 'Credential Access',
    description: 'Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.',
    url: 'https://attack.mitre.org/techniques/T1552/001/'
  },
  'xss-patterns': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    url: 'https://attack.mitre.org/techniques/T1059/'
  },
  'sql-injection': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system.',
    url: 'https://attack.mitre.org/techniques/T1190/'
  },
  'missing-security-headers': {
    id: 'T1562.001',
    name: 'Disable or Modify Tools',
    tactic: 'Defense Evasion',
    description: 'Adversaries may modify and/or disable security tools to avoid detection.',
    url: 'https://attack.mitre.org/techniques/T1562/001/'
  },
  'cors-misconfiguration': {
    id: 'T1213',
    name: 'Data from Information Repositories',
    tactic: 'Collection',
    description: 'Adversaries may leverage information repositories to mine valuable information.',
    url: 'https://attack.mitre.org/techniques/T1213/'
  },
  'ssl-certificate': {
    id: 'T1040',
    name: 'Network Sniffing',
    tactic: 'Credential Access',
    description: 'Adversaries may sniff network traffic to capture information about an environment.',
    url: 'https://attack.mitre.org/techniques/T1040/'
  },
  'open-redirect': {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    url: 'https://attack.mitre.org/techniques/T1566/'
  },
  'directory-indexing-enabled': {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of valid accounts.',
    url: 'https://attack.mitre.org/techniques/T1087/'
  },
  'deprecated-js-libraries': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may exploit software vulnerabilities in public-facing applications.',
    url: 'https://attack.mitre.org/techniques/T1190/'
  },
  'mixed-content': {
    id: 'T1557',
    name: 'Man-in-the-Middle',
    tactic: 'Credential Access',
    description: 'Adversaries may position themselves between two or more networked devices.',
    url: 'https://attack.mitre.org/techniques/T1557/'
  },
  'insecure-cookies': {
    id: 'T1539',
    name: 'Steal Web Session Cookie',
    tactic: 'Credential Access',
    description: 'Adversaries may steal web application or service session cookies.',
    url: 'https://attack.mitre.org/techniques/T1539/'
  },
  'exposed-admin-panel': {
    id: 'T1087',
    name: 'Account Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to discover administrative interfaces and accounts.',
    url: 'https://attack.mitre.org/techniques/T1087/'
  },
  'exposed-config-file': {
    id: 'T1552.001',
    name: 'Credentials In Files',
    tactic: 'Credential Access',
    description: 'Adversaries may search for configuration files containing credentials.',
    url: 'https://attack.mitre.org/techniques/T1552/001/'
  },
  'exposed-git': {
    id: 'T1213.003',
    name: 'Code Repositories',
    tactic: 'Collection',
    description: 'Adversaries may leverage code repositories to collect sensitive information.',
    url: 'https://attack.mitre.org/techniques/T1213/003/'
  },
  'missing-hsts': {
    id: 'T1557.002',
    name: 'ARP Cache Poisoning',
    tactic: 'Credential Access',
    description: 'Without HSTS, attackers may downgrade connections to HTTP.',
    url: 'https://attack.mitre.org/techniques/T1557/002/'
  },
  'missing-csp': {
    id: 'T1059.007',
    name: 'JavaScript',
    tactic: 'Execution',
    description: 'Without CSP, adversaries can inject and execute malicious JavaScript.',
    url: 'https://attack.mitre.org/techniques/T1059/007/'
  },
  'open-ftp': {
    id: 'T1105',
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    description: 'Open FTP can be used to transfer tools and payloads.',
    url: 'https://attack.mitre.org/techniques/T1105/'
  },
  'default': {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'General vulnerability exploitation.',
    url: 'https://attack.mitre.org/techniques/T1190/'
  }
};

export function getMitreTechnique(issueId: string): MitreTechnique {
  return MITRE_MAPPINGS[issueId] || MITRE_MAPPINGS['default'];
}

export function calculateMitreSeverity(technique: MitreTechnique): 'low' | 'medium' | 'high' {
  // Map MITRE tactics to severity
  const tacticSeverity: Record<string, 'low' | 'medium' | 'high'> = {
    'Initial Access': 'high',
    'Execution': 'high',
    'Credential Access': 'high',
    'Defense Evasion': 'medium',
    'Collection': 'medium',
    'Discovery': 'low',
    'Command and Control': 'medium'
  };
  
  return tacticSeverity[technique.tactic] || 'medium';
}
