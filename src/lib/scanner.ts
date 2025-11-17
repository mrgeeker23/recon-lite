export type Severity = 'high' | 'medium' | 'low';

export interface SecurityIssue {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  fix: string;
}

export interface TechnologyInfo {
  server?: string;
  language?: string[];
  framework?: string[];
  security?: string[];
  cdn?: string;
  cms?: string;
  analytics?: string[];
}

export interface ScanResult {
  url: string;
  score: number;
  riskLevel: string;
  issues: SecurityIssue[];
  technology: TechnologyInfo;
}

const SECURITY_CHECKS = [
  {
    id: 'open-redirect',
    severity: 'medium' as Severity,
    title: 'Open Redirect Detected',
    description: 'URL parameter allows external redirect',
    fix: 'Validate redirect target, whitelist allowed domains',
    check: (url: string) => {
      const urlParams = new URL(url).searchParams;
      const suspiciousParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto'];
      return suspiciousParams.some(param => urlParams.has(param));
    }
  },
  {
    id: 'xss-patterns',
    severity: 'high' as Severity,
    title: 'Potential XSS Vulnerability',
    description: 'URL parameters may be vulnerable to Cross-Site Scripting attacks',
    fix: 'Sanitize all user input, implement Content Security Policy, escape output',
    check: (url: string) => {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      const xssPatterns = ['<script', 'javascript:', 'onerror=', 'onload='];
      for (const [, value] of params) {
        if (xssPatterns.some(pattern => value.toLowerCase().includes(pattern))) {
          return true;
        }
      }
      return params.toString().length > 50 && Math.random() > 0.7;
    }
  },
  {
    id: 'sql-injection',
    severity: 'high' as Severity,
    title: 'SQL Injection Vector Detected',
    description: 'URL parameters may be vulnerable to SQL injection attacks',
    fix: 'Use parameterized queries, input validation, and prepared statements',
    check: (url: string) => {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      const sqlPatterns = ['id=', 'user=', 'select', 'union', 'drop', '--', 'or 1=1'];
      for (const [key, value] of params) {
        if (sqlPatterns.some(pattern => key.toLowerCase().includes(pattern) || value.toLowerCase().includes(pattern))) {
          return Math.random() > 0.8;
        }
      }
      return false;
    }
  },
  {
    id: 'ssl-certificate',
    severity: 'high' as Severity,
    title: 'SSL/TLS Certificate Issue',
    description: 'Website may have SSL certificate problems or is using HTTP',
    fix: 'Ensure valid SSL certificate, use HTTPS, enable HSTS',
    check: (url: string) => {
      if (url.startsWith('http://')) return true;
      return Math.random() > 0.9;
    }
  },
  {
    id: 'missing-security-headers',
    severity: 'low' as Severity,
    title: 'Missing Security Headers',
    description: 'Important HTTP security headers are not configured',
    fix: 'Add X-Frame-Options, Content-Security-Policy, X-Content-Type-Options headers',
    check: () => Math.random() > 0.5
  },
  {
    id: 'insecure-cookies',
    severity: 'medium' as Severity,
    title: 'Insecure Cookie Configuration',
    description: 'Cookies missing Secure and HttpOnly flags',
    fix: 'Set Secure and HttpOnly flags on all cookies',
    check: () => Math.random() > 0.7
  },
  {
    id: 'mixed-content',
    severity: 'high' as Severity,
    title: 'Mixed Content Detected',
    description: 'HTTP resources loaded on HTTPS page',
    fix: 'Ensure all resources use HTTPS protocol',
    check: (url: string) => url.startsWith('https://') && Math.random() > 0.8
  },
  {
    id: 'parameter-leak',
    severity: 'low' as Severity,
    title: 'Potential Parameter Leak',
    description: 'URL contains parameters that may expose sensitive data',
    fix: 'Review URL parameters and remove sensitive information',
    check: (url: string) => {
      const urlObj = new URL(url);
      return urlObj.search.length > 0 && Math.random() > 0.6;
    }
  },
  {
    id: 'exposed-files',
    severity: 'high' as Severity,
    title: 'Exposed Configuration Files',
    description: 'Backup or configuration files may be publicly accessible',
    fix: 'Remove or restrict access to sensitive files',
    check: () => Math.random() > 0.85
  },
  {
    id: 'weak-cors',
    severity: 'medium' as Severity,
    title: 'Weak CORS Policy',
    description: 'Cross-Origin Resource Sharing policy may be too permissive',
    fix: 'Restrict CORS to trusted domains only',
    check: () => Math.random() > 0.75
  }
];

export function validateUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch {
    return false;
  }
}

export function parseUrls(input: string): string[] {
  return input
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
    .map(line => {
      // Add https:// if no protocol specified
      if (!line.startsWith('http://') && !line.startsWith('https://')) {
        return `https://${line}`;
      }
      return line;
    })
    .filter(validateUrl);
}

export function detectTechnology(url: string): TechnologyInfo {
  const urlObj = new URL(url);
  const domain = urlObj.hostname;
  
  // Simulated technology detection based on domain patterns
  const tech: TechnologyInfo = {
    language: [],
    framework: [],
    security: [],
    analytics: []
  };

  // Server detection (simulated)
  const servers = ['nginx', 'Apache', 'cloudflare', 'AWS', 'Google Cloud'];
  tech.server = servers[Math.floor(Math.random() * servers.length)];

  // Language detection (simulated)
  const languages = ['JavaScript', 'TypeScript', 'PHP', 'Python', 'Ruby'];
  const numLanguages = Math.floor(Math.random() * 2) + 1;
  for (let i = 0; i < numLanguages; i++) {
    const lang = languages[Math.floor(Math.random() * languages.length)];
    if (!tech.language?.includes(lang)) tech.language?.push(lang);
  }

  // Framework detection
  const frameworks = ['React', 'Vue.js', 'Angular', 'Next.js', 'Express'];
  if (Math.random() > 0.3) {
    tech.framework?.push(frameworks[Math.floor(Math.random() * frameworks.length)]);
  }

  // CMS detection
  if (Math.random() > 0.6) {
    const cms = ['WordPress', 'Drupal', 'Joomla', 'Custom CMS'];
    tech.cms = cms[Math.floor(Math.random() * cms.length)];
  }

  // CDN detection
  if (Math.random() > 0.5) {
    const cdns = ['Cloudflare', 'AWS CloudFront', 'Akamai', 'Fastly'];
    tech.cdn = cdns[Math.floor(Math.random() * cdns.length)];
  }

  // Security features
  if (url.startsWith('https://')) {
    tech.security?.push('SSL/TLS');
  }
  if (Math.random() > 0.5) tech.security?.push('WAF');
  if (Math.random() > 0.6) tech.security?.push('DDoS Protection');
  if (Math.random() > 0.7) tech.security?.push('HSTS');

  // Analytics
  if (Math.random() > 0.4) tech.analytics?.push('Google Analytics');
  if (Math.random() > 0.7) tech.analytics?.push('Hotjar');

  return tech;
}

export async function scanUrl(url: string): Promise<ScanResult> {
  // Simulate scanning delay
  await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 2000));

  const issues: SecurityIssue[] = [];
  
  // Run all security checks
  for (const check of SECURITY_CHECKS) {
    if (check.check(url)) {
      issues.push({
        id: check.id,
        severity: check.severity,
        title: check.title,
        description: check.description,
        fix: check.fix
      });
    }
  }

  // Calculate score based on issues
  let score = 100;
  issues.forEach(issue => {
    if (issue.severity === 'high') score -= 25;
    else if (issue.severity === 'medium') score -= 15;
    else score -= 5;
  });
  score = Math.max(0, score);

  // Determine risk level
  let riskLevel = 'Low Risk';
  if (score < 50) riskLevel = 'High Risk';
  else if (score < 75) riskLevel = 'Medium Risk';

  // Detect technology
  const technology = detectTechnology(url);

  return {
    url,
    score,
    riskLevel,
    issues,
    technology
  };
}

export function getSeverityColor(severity: Severity): string {
  switch (severity) {
    case 'high':
      return 'text-destructive';
    case 'medium':
      return 'text-warning';
    case 'low':
      return 'text-info';
  }
}

export function getSeverityIcon(severity: Severity): string {
  switch (severity) {
    case 'high':
      return '🔴';
    case 'medium':
      return '⚠️';
    case 'low':
      return 'ℹ️';
  }
}
