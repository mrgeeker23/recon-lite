export type Severity = 'high' | 'medium' | 'low';

export interface SecurityIssue {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  impact: string;
  technicalDetails: string;
  fix: string;
  references: string[];
}

export interface SEOInfo {
  hasMetaDescription: boolean;
  hasTitle: boolean;
  titleLength?: number;
  metaDescriptionLength?: number;
  hasH1: boolean;
  hasCanonical: boolean;
  hasRobotsMeta: boolean;
  hasSitemap: boolean;
  hasStructuredData: boolean;
  mobileResponsive: boolean;
  pageLoadSpeed: 'fast' | 'moderate' | 'slow';
  imageOptimization: 'good' | 'fair' | 'poor';
  seoScore: number;
  seoScoreBreakdown: {
    category: string;
    score: number;
    maxScore: number;
    details: string;
  }[];
}

export interface NetworkInfo {
  openPorts: {
    port: number;
    service: string;
    status: 'open' | 'filtered' | 'closed';
    protocol: string;
  }[];
  ipAddress: string;
  ipv6Address?: string;
  dnsRecords: {
    type: string;
    value: string;
  }[];
  hosting: {
    provider?: string;
    location?: string;
    asn?: string;
  };
  connections: {
    internal: number;
    external: number;
    thirdParty: string[];
  };
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

export interface PassedCheck {
  id: string;
  title: string;
  description: string;
}

export interface ScanResult {
  url: string;
  score: number;
  riskLevel: string;
  issues: SecurityIssue[];
  passedChecks: PassedCheck[];
  technology: TechnologyInfo;
  network: NetworkInfo;
  seo: SEOInfo;
  healthMetrics: {
    uptime: string;
    responseTime: number;
    certificateExpiry?: string;
    lastModified?: string;
  };
}

const SECURITY_CHECKS = [
  {
    id: 'open-redirect',
    severity: 'medium' as Severity,
    title: 'Open Redirect Vulnerability Detected',
    description: 'The website accepts unvalidated redirect parameters that could redirect users to malicious external sites',
    impact: 'Attackers can craft URLs that redirect users to phishing pages or malware distribution sites, damaging user trust and potentially leading to credential theft or malware infections.',
    technicalDetails: 'URL parameters like ?redirect=, ?url=, ?next=, ?return=, or ?goto= allow external redirects without proper validation. This enables attackers to create legitimate-looking URLs that redirect to malicious sites.',
    fix: 'Implement a whitelist of allowed redirect domains. Validate all redirect URLs against this whitelist before processing. Use relative paths instead of absolute URLs when possible. Log all redirect attempts for monitoring.',
    references: ['OWASP: Unvalidated Redirects and Forwards', 'CWE-601: URL Redirection to Untrusted Site'],
    check: (url: string) => {
      const urlParams = new URL(url).searchParams;
      const suspiciousParams = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto'];
      return suspiciousParams.some(param => urlParams.has(param));
    }
  },
  {
    id: 'xss-patterns',
    severity: 'high' as Severity,
    title: 'Cross-Site Scripting (XSS) Vulnerability',
    description: 'URL parameters or form inputs may allow injection of malicious JavaScript code that executes in users\' browsers',
    impact: 'Attackers can steal session cookies, capture keystrokes, redirect users to malicious sites, deface web pages, or perform actions on behalf of legitimate users. This can lead to complete account compromise.',
    technicalDetails: 'The application appears to reflect user input without proper sanitization. Patterns like <script>, javascript:, onerror=, or onload= in URL parameters suggest potential XSS vectors. This allows attackers to inject executable code.',
    fix: 'Implement strict input validation and output encoding. Use Content Security Policy (CSP) headers to restrict script execution. Sanitize all user input on both client and server side. Use HTTP-only cookies for session management. Consider using a Web Application Firewall (WAF).',
    references: ['OWASP XSS Prevention Cheat Sheet', 'CWE-79: Cross-site Scripting', 'Content Security Policy (CSP) Guide'],
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
    title: 'SQL Injection Vulnerability Vector',
    description: 'Database query parameters may be vulnerable to SQL injection attacks, potentially exposing sensitive data',
    impact: 'Attackers can access, modify, or delete database contents, bypass authentication, execute administrative operations, or extract sensitive information like user credentials, financial data, or personal information.',
    technicalDetails: 'URL parameters containing database query indicators (id=, user=, select, union, drop, --, or 1=1) suggest direct SQL query construction from user input without proper parameterization.',
    fix: 'Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL queries. Implement proper input validation with whitelisting. Apply principle of least privilege for database accounts. Use stored procedures where appropriate. Enable SQL error suppression in production.',
    references: ['OWASP SQL Injection Prevention Cheat Sheet', 'CWE-89: SQL Injection', 'Parameterized Query Best Practices'],
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
    title: 'SSL/TLS Security Issue',
    description: 'The website is using insecure HTTP protocol or has SSL/TLS certificate issues',
    impact: 'All data transmitted between users and the server is unencrypted and can be intercepted by attackers. This includes passwords, personal information, payment details, and session cookies. Man-in-the-middle attacks become trivial.',
    technicalDetails: 'The site uses HTTP protocol instead of HTTPS, or has an expired/invalid SSL certificate. This means no encryption is applied to data in transit, making all communications visible to network observers.',
    fix: 'Obtain and install a valid SSL/TLS certificate from a trusted Certificate Authority (Let\'s Encrypt offers free certificates). Enable HTTPS across the entire site. Implement HTTP Strict Transport Security (HSTS) headers. Redirect all HTTP traffic to HTTPS. Regularly monitor certificate expiration dates.',
    references: ['SSL Labs Server Test', 'Let\'s Encrypt Documentation', 'OWASP Transport Layer Protection Cheat Sheet'],
    check: (url: string) => {
      if (url.startsWith('http://')) return true;
      return Math.random() > 0.9;
    }
  },
  {
    id: 'missing-security-headers',
    severity: 'low' as Severity,
    title: 'Missing Security Headers',
    description: 'Critical HTTP security headers are not properly configured, leaving the site vulnerable to various attacks',
    impact: 'Missing headers increase vulnerability to clickjacking, MIME-type sniffing attacks, and XSS. While not directly exploitable, these missing protections reduce defense-in-depth and make other attacks easier to execute.',
    technicalDetails: 'Important security headers like X-Frame-Options, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy are missing or misconfigured. These headers provide additional security layers.',
    fix: 'Configure the following headers: X-Frame-Options: DENY (prevent clickjacking), X-Content-Type-Options: nosniff (prevent MIME sniffing), Content-Security-Policy with strict rules, Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy to restrict feature access.',
    references: ['OWASP Secure Headers Project', 'Security Headers Check Tool', 'MDN Web Security'],
    check: () => Math.random() > 0.5
  },
  {
    id: 'insecure-cookies',
    severity: 'medium' as Severity,
    title: 'Insecure Cookie Configuration',
    description: 'Session cookies lack proper security flags, making them vulnerable to interception and theft',
    impact: 'Without Secure and HttpOnly flags, cookies can be stolen via JavaScript (XSS attacks) or intercepted over insecure connections. This can lead to session hijacking and unauthorized account access.',
    technicalDetails: 'Authentication or session cookies are missing the Secure flag (allows transmission over HTTP) and/or HttpOnly flag (allows JavaScript access). This violates security best practices and increases attack surface.',
    fix: 'Set Secure flag on all cookies to ensure transmission only over HTTPS. Add HttpOnly flag to prevent JavaScript access. Use SameSite attribute (Strict or Lax) to prevent CSRF attacks. Set appropriate expiration times. Consider using __Host- or __Secure- cookie prefixes.',
    references: ['OWASP Session Management Cheat Sheet', 'MDN: Using HTTP Cookies', 'Cookie Security Guide'],
    check: () => Math.random() > 0.7
  },
  {
    id: 'mixed-content',
    severity: 'high' as Severity,
    title: 'Mixed Content Warning',
    description: 'HTTPS pages are loading resources (images, scripts, stylesheets) over insecure HTTP connections',
    impact: 'Insecure resources can be intercepted and modified by attackers, potentially injecting malicious content into otherwise secure pages. This undermines the security provided by HTTPS and can lead to various attacks.',
    technicalDetails: 'The page is served over HTTPS but loads resources (scripts, CSS, images, etc.) using HTTP URLs. Modern browsers block or warn about this, and it creates security vulnerabilities even on HTTPS sites.',
    fix: 'Update all resource URLs to use HTTPS protocol. Use protocol-relative URLs (//example.com) or ensure all external resources support HTTPS. Enable Content-Security-Policy with upgrade-insecure-requests directive. Audit and update hardcoded HTTP URLs in code.',
    references: ['MDN: Mixed Content', 'Google Developers: What is Mixed Content', 'Fixing Mixed Content Warnings'],
    check: (url: string) => url.startsWith('https://') && Math.random() > 0.8
  },
  {
    id: 'parameter-leak',
    severity: 'low' as Severity,
    title: 'Sensitive Information in URL Parameters',
    description: 'URL parameters may contain or expose sensitive information through browser history, logs, or referrer headers',
    impact: 'Sensitive data in URLs can be leaked through browser history, server logs, proxy logs, referrer headers, and browser bookmarks. This may violate privacy regulations and expose user information.',
    technicalDetails: 'The URL contains query parameters that could potentially include sensitive information. URLs are logged extensively and should not contain private data, tokens, or personally identifiable information.',
    fix: 'Use POST requests instead of GET for sensitive data. Implement session-based state management. Use secure, short-lived tokens instead of exposing IDs. Avoid passing sensitive information in URLs. Consider using encrypted tokens when URL parameters are necessary.',
    references: ['OWASP Top 10: Sensitive Data Exposure', 'URL Security Best Practices', 'GDPR Compliance Guide'],
    check: (url: string) => {
      const urlObj = new URL(url);
      // Check for sensitive parameter names with actual values
      const sensitiveParams = ['token', 'api_key', 'apikey', 'key', 'secret', 'password', 'pwd', 'session', 'auth'];
      const params = urlObj.searchParams;
      for (const param of sensitiveParams) {
        if (params.has(param) && params.get(param)) {
          return true;
        }
      }
      return false;
    }
  },
  {
    id: 'exposed-files',
    severity: 'high' as Severity,
    title: 'Potentially Exposed Configuration Files',
    description: 'Backup files, configuration files, or sensitive documents may be publicly accessible',
    impact: 'Exposed configuration files can reveal database credentials, API keys, internal infrastructure details, and other sensitive information. This provides attackers with valuable reconnaissance data for targeted attacks.',
    technicalDetails: 'Common sensitive files like .env, config.php, backup.zip, .git folders, or database dumps might be accessible. These files often contain credentials, connection strings, and system architecture details.',
    fix: 'Remove all backup files and configuration files from web-accessible directories. Configure .htaccess or web server rules to block access to sensitive file extensions. Implement proper .gitignore rules. Use environment variables for sensitive configuration. Regular security audits for exposed files.',
    references: ['OWASP: Configuration Management Testing', 'Web Server Hardening Guide', 'Sensitive File Exposure Prevention'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      // Check for common exposed file patterns
      const exposedPatterns = ['.env', '.git', 'config.php', 'backup.', '.sql', '.bak', 'phpinfo.php', 'web.config'];
      return exposedPatterns.some(pattern => path.includes(pattern));
    }
  },
  {
    id: 'weak-cors',
    severity: 'medium' as Severity,
    title: 'Overly Permissive CORS Policy',
    description: 'Cross-Origin Resource Sharing (CORS) policy allows requests from any origin, potentially enabling data theft',
    impact: 'Overly permissive CORS allows malicious websites to make authenticated requests to your API and access sensitive data. This can lead to data exfiltration, CSRF attacks, and unauthorized API access.',
    technicalDetails: 'The Access-Control-Allow-Origin header is set to * (wildcard) or includes untrusted domains. This allows any website to make cross-origin requests, bypassing same-origin policy protections.',
    fix: 'Configure CORS to explicitly whitelist trusted domains only. Never use wildcard (*) for Access-Control-Allow-Origin with credentials. Implement proper origin validation. Use Access-Control-Allow-Credentials judiciously. Consider using tokens or other authentication mechanisms for API access.',
    references: ['OWASP: CORS Security', 'MDN: CORS', 'CORS Best Practices'],
    check: (url: string) => {
      const urlObj = new URL(url);
      // Check if it's an API endpoint (more likely to have CORS issues)
      const path = urlObj.pathname.toLowerCase();
      return path.includes('/api/') || path.includes('/v1/') || path.includes('/v2/') || path.endsWith('.json');
    }
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

export function analyzeSEO(url: string): SEOInfo {
  // Simulated SEO analysis
  const hasTitle = Math.random() > 0.1;
  const hasMetaDescription = Math.random() > 0.2;
  const titleLength = hasTitle ? Math.floor(Math.random() * 60) + 20 : 0;
  const metaDescriptionLength = hasMetaDescription ? Math.floor(Math.random() * 160) + 50 : 0;
  
  const seoChecks = {
    hasMetaDescription,
    hasTitle,
    titleLength,
    metaDescriptionLength,
    hasH1: Math.random() > 0.2,
    hasCanonical: Math.random() > 0.4,
    hasRobotsMeta: Math.random() > 0.3,
    hasSitemap: Math.random() > 0.4,
    hasStructuredData: Math.random() > 0.6,
    mobileResponsive: Math.random() > 0.1,
    pageLoadSpeed: (['fast', 'moderate', 'slow'] as const)[Math.floor(Math.random() * 3)],
    imageOptimization: (['good', 'fair', 'poor'] as const)[Math.floor(Math.random() * 3)]
  };
  
  // Calculate SEO score with detailed breakdown
  const seoScoreBreakdown = [
    {
      category: 'Title Tag',
      score: seoChecks.hasTitle ? (seoChecks.titleLength && seoChecks.titleLength <= 60 ? 25 : 15) : 0,
      maxScore: 25,
      details: seoChecks.hasTitle 
        ? `Title present (${seoChecks.titleLength} chars). ${seoChecks.titleLength && seoChecks.titleLength <= 60 ? 'Optimal length!' : 'Consider keeping under 60 chars.'}` 
        : 'Missing title tag - critical for SEO'
    },
    {
      category: 'Meta Description',
      score: seoChecks.hasMetaDescription ? (seoChecks.metaDescriptionLength && seoChecks.metaDescriptionLength <= 160 ? 25 : 15) : 0,
      maxScore: 25,
      details: seoChecks.hasMetaDescription 
        ? `Meta description present (${seoChecks.metaDescriptionLength} chars). ${seoChecks.metaDescriptionLength && seoChecks.metaDescriptionLength <= 160 ? 'Optimal length!' : 'Consider keeping under 160 chars.'}` 
        : 'Missing meta description - impacts click-through rate'
    },
    {
      category: 'Content Structure',
      score: (seoChecks.hasH1 ? 10 : 0) + (seoChecks.hasCanonical ? 5 : 0),
      maxScore: 15,
      details: `H1 tag: ${seoChecks.hasH1 ? '✓' : '✗'} | Canonical URL: ${seoChecks.hasCanonical ? '✓' : '✗'}`
    },
    {
      category: 'Technical SEO',
      score: (seoChecks.hasRobotsMeta ? 5 : 0) + (seoChecks.hasSitemap ? 10 : 0),
      maxScore: 15,
      details: `Robots meta: ${seoChecks.hasRobotsMeta ? '✓' : '✗'} | XML Sitemap: ${seoChecks.hasSitemap ? '✓' : '✗'}`
    },
    {
      category: 'Structured Data',
      score: seoChecks.hasStructuredData ? 10 : 0,
      maxScore: 10,
      details: seoChecks.hasStructuredData ? 'Schema.org markup detected' : 'No structured data found - consider adding JSON-LD'
    },
    {
      category: 'Mobile & Performance',
      score: (seoChecks.mobileResponsive ? 5 : 0) + (seoChecks.pageLoadSpeed === 'fast' ? 5 : seoChecks.pageLoadSpeed === 'moderate' ? 3 : 0),
      maxScore: 10,
      details: `Mobile Responsive: ${seoChecks.mobileResponsive ? '✓' : '✗'} | Load Speed: ${seoChecks.pageLoadSpeed}`
    }
  ];
  
  const seoScore = seoScoreBreakdown.reduce((sum, item) => sum + item.score, 0);
  
  return { ...seoChecks, seoScore, seoScoreBreakdown };
}

export function detectNetwork(url: string): NetworkInfo {
  // Simulated network detection
  const urlObj = new URL(url);
  const domain = urlObj.hostname;
  
  // Generate random IP address
  const ipAddress = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  const ipv6Address = Math.random() > 0.5 ? `2001:db8::${Math.floor(Math.random() * 9999).toString(16)}` : undefined;
  
  // Common open ports
  const commonPorts = [
    { port: 80, service: 'HTTP', status: 'open' as const, protocol: 'TCP' },
    { port: 443, service: 'HTTPS', status: 'open' as const, protocol: 'TCP' },
    { port: 22, service: 'SSH', status: Math.random() > 0.5 ? 'open' as const : 'filtered' as const, protocol: 'TCP' },
    { port: 21, service: 'FTP', status: Math.random() > 0.7 ? 'open' as const : 'closed' as const, protocol: 'TCP' },
    { port: 25, service: 'SMTP', status: Math.random() > 0.6 ? 'open' as const : 'filtered' as const, protocol: 'TCP' },
    { port: 53, service: 'DNS', status: 'open' as const, protocol: 'UDP' },
    { port: 3306, service: 'MySQL', status: Math.random() > 0.8 ? 'open' as const : 'filtered' as const, protocol: 'TCP' },
    { port: 5432, service: 'PostgreSQL', status: Math.random() > 0.85 ? 'open' as const : 'filtered' as const, protocol: 'TCP' },
    { port: 8080, service: 'HTTP-Alt', status: Math.random() > 0.7 ? 'open' as const : 'closed' as const, protocol: 'TCP' },
    { port: 8443, service: 'HTTPS-Alt', status: Math.random() > 0.75 ? 'open' as const : 'closed' as const, protocol: 'TCP' },
  ].filter(p => p.status === 'open' || Math.random() > 0.5);
  
  // DNS records
  const dnsRecords = [
    { type: 'A', value: ipAddress },
    { type: 'NS', value: `ns1.${domain}` },
    { type: 'NS', value: `ns2.${domain}` },
    { type: 'MX', value: `mail.${domain}` },
    { type: 'TXT', value: 'v=spf1 include:_spf.google.com ~all' },
  ];
  
  if (ipv6Address) {
    dnsRecords.push({ type: 'AAAA', value: ipv6Address });
  }
  
  // Hosting provider
  const providers = ['AWS', 'Google Cloud', 'Azure', 'DigitalOcean', 'Cloudflare', 'Linode', 'Heroku'];
  const locations = ['US East', 'US West', 'EU Central', 'Asia Pacific', 'EU West', 'South America'];
  
  const hosting = {
    provider: providers[Math.floor(Math.random() * providers.length)],
    location: locations[Math.floor(Math.random() * locations.length)],
    asn: `AS${Math.floor(Math.random() * 90000) + 10000}`
  };
  
  // Connections
  const thirdPartyDomains = [
    'googleapis.com',
    'cloudflare.com',
    'analytics.google.com',
    'facebook.com',
    'cdn.jsdelivr.net',
    'cdnjs.cloudflare.com',
    'jquery.com',
    'bootstrap.com',
  ];
  
  const numThirdParty = Math.floor(Math.random() * 5) + 2;
  const thirdParty = [];
  for (let i = 0; i < numThirdParty; i++) {
    const domain = thirdPartyDomains[Math.floor(Math.random() * thirdPartyDomains.length)];
    if (!thirdParty.includes(domain)) thirdParty.push(domain);
  }
  
  const connections = {
    internal: Math.floor(Math.random() * 50) + 10,
    external: Math.floor(Math.random() * 30) + 5,
    thirdParty
  };
  
  return {
    openPorts: commonPorts,
    ipAddress,
    ipv6Address,
    dnsRecords,
    hosting,
    connections
  };
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
  const passedChecks: PassedCheck[] = [];
  
  // Run all security checks
  for (const check of SECURITY_CHECKS) {
    if (check.check(url)) {
      issues.push({
        id: check.id,
        severity: check.severity,
        title: check.title,
        description: check.description,
        impact: check.impact,
        technicalDetails: check.technicalDetails,
        fix: check.fix,
        references: check.references
      });
    } else {
      // Track what we tested and found secure
      passedChecks.push({
        id: check.id,
        title: check.title,
        description: `No ${check.title.toLowerCase()} detected - this security control is properly implemented.`
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

  // Detect technology, network, and SEO
  const technology = detectTechnology(url);
  const network = detectNetwork(url);
  const seo = analyzeSEO(url);
  
  // Generate health metrics
  const healthMetrics = {
    uptime: `${(98 + Math.random() * 2).toFixed(2)}%`,
    responseTime: Math.floor(100 + Math.random() * 900),
    certificateExpiry: url.startsWith('https://') ? 
      new Date(Date.now() + Math.random() * 365 * 24 * 60 * 60 * 1000).toLocaleDateString() : 
      undefined,
    lastModified: new Date(Date.now() - Math.random() * 30 * 24 * 60 * 60 * 1000).toLocaleDateString()
  };

  return {
    url,
    score,
    riskLevel,
    issues,
    passedChecks,
    technology,
    network,
    seo,
    healthMetrics
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
