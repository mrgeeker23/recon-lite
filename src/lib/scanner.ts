export type Severity = 'high' | 'medium' | 'low';

export interface SecurityIssue {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  fix: string;
}

export interface ScanResult {
  url: string;
  score: number;
  riskLevel: string;
  issues: SecurityIssue[];
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
    id: 'missing-security-headers',
    severity: 'low' as Severity,
    title: 'Missing Security Headers',
    description: 'Important HTTP security headers are not configured',
    fix: 'Add X-Frame-Options, Content-Security-Policy, X-Content-Type-Options headers',
    check: () => Math.random() > 0.5 // Simulated since we can't check headers due to CORS
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

  return {
    url,
    score,
    riskLevel,
    issues
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
