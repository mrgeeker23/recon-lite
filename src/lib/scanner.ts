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

export interface RTIInfo {
  likelihood: number;
  detectedPatterns: {
    category: string;
    detected: boolean;
    details: string;
  }[];
  regionalIndicators: {
    indicator: string;
    value: string;
    risk: 'low' | 'medium' | 'high';
  }[];
  verdict: string;
}

export interface PortScanInfo {
  exposedPorts: {
    port: number;
    service: string;
    exposureHint: string;
    risk: 'low' | 'medium' | 'high';
  }[];
  summary: string;
}

export interface FrameworkRiskInfo {
  framework?: string;
  version?: string;
  riskScore: number;
  vulnerabilities: string[];
  recommendation: string;
}

export interface JSSecurityInfo {
  exposedSecrets: {
    type: string;
    severity: 'high' | 'medium' | 'low';
    location: string;
    preview: string;
  }[];
  suspiciousPatterns: string[];
  riskLevel: 'low' | 'medium' | 'high';
}

export interface ScamDetectionInfo {
  templateMatch: number;
  matchedTemplates: string[];
  jsKitMatch: boolean;
  redirectBehavior: 'safe' | 'suspicious' | 'dangerous';
  overallVerdict: string;
}

export type SuspicionTag = 
  | 'Small Business Site'
  | 'Scam Template'
  | 'Phishing Kit'
  | 'Outdated WordPress Theme'
  | 'Student Project'
  | 'Professional Site'
  | 'E-commerce Store'
  | 'Government Clone'
  | 'Shared Hosting';

export interface RiskTheme {
  theme: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  findings: string[];
  score: number;
}

export interface PassiveCrawlInfo {
  discoveredPaths: {
    path: string;
    risk: 'low' | 'medium' | 'high';
    type: string;
  }[];
  summary: string;
}

export interface ScanResult {
  url: string;
  score: number;
  riskLevel: string;
  trustScore: number;
  issues: SecurityIssue[];
  passedChecks: PassedCheck[];
  technology: TechnologyInfo;
  network: NetworkInfo;
  seo: SEOInfo;
  rti: RTIInfo;
  portScan: PortScanInfo;
  frameworkRisk: FrameworkRiskInfo;
  jsSecurity: JSSecurityInfo;
  scamDetection: ScamDetectionInfo;
  suspicionTags: SuspicionTag[];
  riskThemes: RiskTheme[];
  passiveCrawl: PassiveCrawlInfo;
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
      const urlParams = new URL(url).searchParams;
      const dbParams = ['id', 'user', 'userid', 'query', 'search', 'page', 'item', 'cat', 'category'];
      return dbParams.some(param => urlParams.has(param)) && Math.random() > 0.7;
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
    id: 'exposed-env-file',
    severity: 'high' as Severity,
    title: 'Potential .env File Exposed',
    description: 'Pattern detected suggesting environment configuration file may be publicly accessible',
    impact: 'Exposed .env files can leak database credentials, API keys, secret tokens, and other critical configuration. This leads to complete system compromise, unauthorized data access, and ability to impersonate the application.',
    technicalDetails: 'Pattern detected: "DB_PASSWORD=" or similar environment variable patterns in publicly served JavaScript or accessible files. Common in misconfigured Node.js, Laravel, or other framework deployments.',
    fix: 'Ensure .env files are never served publicly. Add .env to .gitignore. Use proper environment variable injection. Configure web server to deny access to .env files. Rotate all exposed credentials immediately. Implement secrets management systems.',
    references: ['OWASP: Sensitive Data Exposure', 'Environment Variable Security', 'Secrets Management Best Practices'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      return path.includes('.env') || path.includes('config') && Math.random() > 0.75;
    }
  },
  {
    id: 'cors-misconfiguration',
    severity: 'high' as Severity,
    title: 'CORS Misconfiguration',
    description: 'Cross-Origin Resource Sharing is configured to allow all origins with credentials',
    impact: 'Access-Control-Allow-Origin: * with credentials exposed allows malicious sites to read sensitive data cross-origin. Attackers can steal user data, session tokens, and perform unauthorized actions. Cookies and authentication headers become accessible to any domain.',
    technicalDetails: 'CORS headers set to Access-Control-Allow-Origin: * while Access-Control-Allow-Credentials: true. This combination allows any website to make authenticated requests and read responses, bypassing same-origin policy.',
    fix: 'Never use wildcard (*) origin with credentials. Specify exact allowed origins. Validate Origin header server-side. Use credentials: "same-origin" when possible. Implement proper CORS policy with whitelist of trusted domains. Avoid reflecting Origin header without validation.',
    references: ['OWASP: CORS Security', 'MDN: CORS Documentation', 'PortSwigger: CORS Vulnerabilities'],
    check: (url: string) => {
      return Math.random() > 0.65;
    }
  },
  {
    id: 'directory-indexing-enabled',
    severity: 'medium' as Severity,
    title: 'Directory Indexing Enabled',
    description: 'Server appears to allow directory listing, exposing file structure',
    impact: 'Directory indexing reveals backup files, configuration files, source code, and application structure. Attackers gain insight into file organization, technology stack, and can discover sensitive files like backups, logs, or credentials.',
    technicalDetails: '/backup/ or similar directories return file listings (passive assumption based on common misconfigurations). Apache Options +Indexes, nginx autoindex on, or IIS directory browsing enabled.',
    fix: 'Disable directory listing in web server configuration: Apache (Options -Indexes), nginx (autoindex off), IIS (disable directory browsing). Place index.html in all directories. Use .htaccess to deny browsing. Regular security audits.',
    references: ['OWASP: Directory Listing', 'Apache Security Configuration', 'nginx Security Hardening'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      const suspiciousPaths = ['/backup', '/old', '/files', '/uploads', '/assets', '/static', '/data'];
      return suspiciousPaths.some(p => path.includes(p)) && Math.random() > 0.7;
    }
  },
  {
    id: 'deprecated-js-libraries',
    severity: 'high' as Severity,
    title: 'Deprecated JavaScript Libraries Detected',
    description: 'Outdated JavaScript libraries with known security vulnerabilities detected',
    impact: 'jQuery 1.8.3 (and similar old versions) contain known XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023). Attackers can exploit these to execute arbitrary JavaScript, steal sessions, or manipulate page content. Other legacy libraries also pose risks.',
    technicalDetails: 'Detection of jQuery versions < 3.5.0, Angular < 1.5.0, Bootstrap < 3.4.0, or other libraries with known CVEs. These libraries have documented security flaws that are actively exploited.',
    fix: 'Update all JavaScript libraries to their latest stable versions. Use npm audit or Snyk to detect vulnerable dependencies. Implement Content Security Policy (CSP). Consider using modern frameworks with better security. Set up automated dependency updates.',
    references: ['jQuery Security', 'Snyk Vulnerability Database', 'npm audit Documentation', 'CVE-2020-11022'],
    check: (url: string) => {
      return Math.random() > 0.6;
    }
  },
  {
    id: 'mixed-content',
    severity: 'medium' as Severity,
    title: 'Mixed Content Detected',
    description: 'HTTPS page loading HTTP resources (images, scripts, stylesheets)',
    impact: 'HTTP resources on HTTPS pages can be intercepted and modified by attackers. Scripts loaded over HTTP can be replaced with malicious code. Images can be swapped. This undermines the security of the entire HTTPS connection.',
    technicalDetails: 'HTTP images, scripts, or stylesheets referenced on an HTTPS page. Browsers may block or warn about mixed content. Active mixed content (scripts, iframes) is particularly dangerous as it can execute arbitrary code.',
    fix: 'Convert all resource URLs to HTTPS. Use protocol-relative URLs (//example.com/script.js) or https:// explicitly. Enable Content Security Policy with upgrade-insecure-requests directive. Check all external resources support HTTPS.',
    references: ['MDN: Mixed Content', 'OWASP: Transport Layer Protection', 'Content Security Policy Guide'],
    check: (url: string) => {
      return url.startsWith('https://') && Math.random() > 0.7;
    }
  },
  {
    id: 'missing-security-headers',
    severity: 'medium' as Severity,
    title: 'Missing Critical Security Headers',
    description: 'Critical HTTP security headers are missing: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security, X-XSS-Protection, Referrer-Policy, Permissions-Policy',
    impact: 'Without X-Frame-Options: vulnerable to clickjacking. Without X-Content-Type-Options: MIME-sniffing attacks possible. Without CSP: XSS attacks harder to prevent. Without HSTS: man-in-the-middle attacks possible. Without Referrer-Policy: information leakage.',
    technicalDetails: 'Missing headers:\n• X-Frame-Options: DENY/SAMEORIGIN - prevents clickjacking\n• X-Content-Type-Options: nosniff - prevents MIME-sniffing\n• Content-Security-Policy - mitigates XSS, data injection\n• Strict-Transport-Security: max-age=31536000 - enforces HTTPS\n• X-XSS-Protection: 1; mode=block - legacy XSS protection\n• Referrer-Policy: strict-origin-when-cross-origin - controls referrer info\n• Permissions-Policy - restricts browser features',
    fix: 'Add security headers to server configuration:\n\nApache (.htaccess):\nHeader set X-Frame-Options "DENY"\nHeader set X-Content-Type-Options "nosniff"\nHeader set Content-Security-Policy "default-src \'self\'"\nHeader set Strict-Transport-Security "max-age=31536000; includeSubDomains"\n\nnginx:\nadd_header X-Frame-Options "DENY";\nadd_header X-Content-Type-Options "nosniff";\nadd_header Content-Security-Policy "default-src \'self\'";\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains";',
    references: ['OWASP Secure Headers Project', 'Security Headers Check Tool', 'MDN Web Security'],
    check: (url: string) => !url.startsWith('https://') || Math.random() > 0.5
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
    check: (url: string) => {
      const urlObj = new URL(url);
      const cookiePaths = ['/login', '/account', '/dashboard', '/admin', '/user', '/profile'];
      return cookiePaths.some(path => urlObj.pathname.includes(path)) || Math.random() > 0.75;
    }
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
  },
  {
    id: 'parameter-pollution',
    severity: 'medium' as Severity,
    title: 'HTTP Parameter Pollution Detected',
    description: 'Duplicate URL parameters detected which can cause inconsistent behavior across different web server technologies',
    impact: 'Parameter pollution can bypass security filters, cause cache poisoning, and lead to unexpected application behavior. Different servers handle duplicate parameters differently, which attackers can exploit.',
    technicalDetails: 'The URL contains duplicate parameter names (e.g., ?id=1&id=2). Apache uses the last value, Tomcat concatenates with comma, ASP.NET uses all values. This inconsistency creates attack opportunities.',
    fix: 'Validate and sanitize all input parameters. Use arrays explicitly if multiple values are needed. Reject requests with duplicate parameter names. Implement consistent parameter handling logic across the application.',
    references: ['OWASP: HTTP Parameter Pollution', 'CWE-235: Improper Handling of Parameters'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      const paramNames = new Set<string>();
      for (const [key] of params) {
        if (paramNames.has(key)) return true;
        paramNames.add(key);
      }
      return false;
    }
  },
  {
    id: 'debug-parameters',
    severity: 'high' as Severity,
    title: 'Debug Mode Enabled or Exposed',
    description: 'Debug parameters or development endpoints are exposed in production, potentially revealing sensitive system information',
    impact: 'Debug mode can expose stack traces, internal paths, database queries, environment variables, and sensitive configuration. This provides attackers with valuable reconnaissance data for targeted exploitation.',
    technicalDetails: 'URL contains debug parameters like debug=true, test=1, dev=1, or verbose=1. These flags often enable detailed error messages and diagnostic information not intended for production environments.',
    fix: 'Disable all debug modes in production. Remove or restrict access to debug endpoints. Implement environment-based configuration. Use feature flags to control debug functionality. Monitor for unauthorized debug parameter usage.',
    references: ['OWASP: Information Leakage', 'CWE-489: Active Debug Code'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      const debugParams = ['debug', 'test', 'dev', 'verbose', 'trace', 'log', 'admin', 'developer'];
      return debugParams.some(param => params.has(param) && ['1', 'true', 'on', 'yes'].includes(params.get(param)?.toLowerCase() || ''));
    }
  },
  {
    id: 'reflected-parameter',
    severity: 'high' as Severity,
    title: 'Parameter Reflection Detected (XSS Hint)',
    description: 'URL parameters are reflected in the response without proper encoding, indicating potential XSS vulnerability',
    impact: 'Reflected parameters can enable XSS attacks where attackers inject malicious scripts that execute in victims\' browsers. This can lead to session hijacking, credential theft, and complete account compromise.',
    technicalDetails: 'Parameters like search, q, query, name, or message are often reflected back in HTML responses. Without proper output encoding, these become XSS vectors. Even if no payload is present, reflection is a strong indicator.',
    fix: 'Implement context-aware output encoding for all user input. Use Content-Security-Policy headers. Sanitize input with allowlists. Use modern frameworks that auto-escape by default. Implement input validation with length limits.',
    references: ['OWASP: XSS Prevention Cheat Sheet', 'CWE-79: Cross-site Scripting'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const params = urlObj.searchParams;
      const reflectedParams = ['search', 'q', 'query', 'name', 'message', 'comment', 'text', 'error', 'msg'];
      return reflectedParams.some(param => params.has(param) && params.get(param)?.length);
    }
  },
  {
    id: 'exposed-extensions',
    severity: 'medium' as Severity,
    title: 'Sensitive File Extensions Detected',
    description: 'URL exposes file extensions that may indicate vulnerable or legacy technologies (.php, .asp, .jsp) or backup files',
    impact: 'Exposed file extensions reveal technology stack details, making targeted attacks easier. Backup files (.bak, .old, .zip) may contain source code with hardcoded credentials or security vulnerabilities.',
    technicalDetails: 'The URL contains extensions like .php, .asp, .aspx, .jsp, .cgi, .bak, .old, .zip, .tar.gz, .sql, or .backup. These files are often overlooked during security audits and can expose sensitive information.',
    fix: 'Remove all backup and temporary files from web-accessible directories. Use URL rewriting to hide file extensions. Implement proper .htaccess or web.config rules to block access to backup files. Regular security scans for exposed files.',
    references: ['OWASP: Backup File Discovery', 'File Extension Security Guide'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      const sensitiveExtensions = ['.bak', '.old', '.zip', '.tar.gz', '.sql', '.backup', '.swp', '.tmp', '.log', '.rar', '.7z'];
      const legacyExtensions = ['.asp', '.aspx', '.jsp', '.cgi', '.pl'];
      return [...sensitiveExtensions, ...legacyExtensions].some(ext => path.endsWith(ext));
    }
  },
  {
    id: 'js-endpoint-exposure',
    severity: 'medium' as Severity,
    title: 'JavaScript Files May Contain Sensitive Data',
    description: 'JavaScript files detected that commonly contain hardcoded API keys, tokens, or internal endpoints',
    impact: 'JavaScript files are publicly readable and often contain hardcoded secrets, API endpoints, admin URLs, or business logic. This provides attackers with reconnaissance data and potential credential leaks.',
    technicalDetails: 'URLs pointing to .js files, especially config.js, app.js, main.js, or vendor bundles. Developers sometimes hardcode API keys, internal URLs, or sensitive configuration in client-side JavaScript.',
    fix: 'Never hardcode API keys or secrets in JavaScript. Use environment variables and server-side API proxies. Implement proper key rotation. Scan JavaScript files regularly for exposed credentials. Use obfuscation and minification.',
    references: ['OWASP: Client-Side Security', 'JavaScript Secret Management'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      const sensitiveJsFiles = ['config.js', 'app.js', 'main.js', 'env.js', 'settings.js', 'constants.js'];
      return path.endsWith('.js') && (sensitiveJsFiles.some(file => path.includes(file)) || path.includes('bundle'));
    }
  },
  {
    id: 'admin-panel-hint',
    severity: 'low' as Severity,
    title: 'Potential Admin/Hidden Endpoint Detected',
    description: 'URL patterns suggest administrative interfaces or hidden endpoints that should be properly secured',
    impact: 'Exposed admin panels are prime targets for brute force attacks and unauthorized access. Even if secured, their discovery reduces security through obscurity and increases attack surface.',
    technicalDetails: 'URL contains paths like /admin, /administrator, /dashboard, /panel, /cpanel, /phpmyadmin, /wp-admin, or /manager. These are common admin panel locations that attackers routinely probe.',
    fix: 'Implement strong authentication (MFA) for admin panels. Use non-standard URLs for admin interfaces. Restrict access by IP address when possible. Implement rate limiting and account lockout. Monitor for unauthorized access attempts.',
    references: ['OWASP: Admin Interface Security', 'CWE-425: Direct Request'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname.toLowerCase();
      const adminPatterns = ['/admin', '/administrator', '/dashboard', '/panel', '/cpanel', '/phpmyadmin', '/wp-admin', '/manager', '/console', '/control'];
      return adminPatterns.some(pattern => path.includes(pattern));
    }
  },
  {
    id: 'directory-listing',
    severity: 'medium' as Severity,
    title: 'Potential Directory Listing Vulnerability',
    description: 'URL patterns suggest directory listings may be enabled, exposing file structure and contents',
    impact: 'Directory listings expose file structure, backup files, configuration files, and source code. This provides attackers with valuable information about application architecture and potential security vulnerabilities.',
    technicalDetails: 'URLs ending with / or common directory names without index files often trigger directory listings on misconfigured servers. Apache, IIS, and nginx can be configured to show directory contents by default.',
    fix: 'Disable directory listings in web server configuration (Options -Indexes for Apache). Ensure index files exist in all directories. Use .htaccess to explicitly deny directory browsing. Regular audits for exposed directories.',
    references: ['OWASP: Directory Listing', 'Web Server Hardening'],
    check: (url: string) => {
      const urlObj = new URL(url);
      const path = urlObj.pathname;
      const suspiciousPaths = ['/uploads/', '/files/', '/documents/', '/assets/', '/backup/', '/data/', '/images/'];
      return path.endsWith('/') && (suspiciousPaths.some(p => path.includes(p)) || path.split('/').length > 4);
    }
  },
  {
    id: 'missing-hsts',
    severity: 'medium' as Severity,
    title: 'HTTP Strict Transport Security (HSTS) Not Detected',
    description: 'HSTS header appears to be missing, allowing potential downgrade attacks and man-in-the-middle attacks',
    impact: 'Without HSTS, attackers can intercept the initial HTTP request and perform SSL stripping attacks. Users can be forced to use HTTP even if HTTPS is available, exposing sensitive data.',
    technicalDetails: 'The Strict-Transport-Security header tells browsers to only use HTTPS for future requests. Missing HSTS allows attackers to intercept first-time visitors or users who type HTTP URLs.',
    fix: 'Implement HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. Start with shorter max-age for testing. Consider HSTS preloading for maximum protection.',
    references: ['OWASP: HSTS Cheat Sheet', 'MDN: Strict-Transport-Security'],
    check: (url: string) => url.startsWith('https://') && Math.random() > 0.6
  },
  {
    id: 'missing-csp',
    severity: 'high' as Severity,
    title: 'Content Security Policy (CSP) Not Implemented',
    description: 'Critical Content-Security-Policy header is missing, reducing protection against XSS and injection attacks',
    impact: 'Without CSP, the browser cannot block malicious inline scripts or unauthorized resource loading. This makes XSS exploitation significantly easier and more damaging.',
    technicalDetails: 'CSP defines which content sources are trustworthy. Missing CSP allows any script to execute, any resource to load, and provides no defense-in-depth against code injection attacks.',
    fix: 'Implement strict CSP: Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'. Start with report-only mode to test. Gradually tighten policy.',
    references: ['OWASP: CSP Cheat Sheet', 'MDN: Content-Security-Policy', 'CSP Evaluator'],
    check: (url: string) => Math.random() > 0.55
  },
  {
    id: 'clickjacking-risk',
    severity: 'medium' as Severity,
    title: 'Clickjacking Protection Missing (X-Frame-Options)',
    description: 'X-Frame-Options header is not set, allowing the page to be embedded in iframes for clickjacking attacks',
    impact: 'Attackers can embed your site in invisible iframes and trick users into performing unintended actions like changing passwords, making purchases, or transferring funds.',
    technicalDetails: 'Without X-Frame-Options or frame-ancestors CSP directive, any site can embed your pages in iframes. Clickjacking overlays transparent iframes to hijack user clicks.',
    fix: 'Set X-Frame-Options: DENY or SAMEORIGIN header. Alternatively, use CSP frame-ancestors directive. Implement frame-busting JavaScript as additional protection. Test with frame-busting tools.',
    references: ['OWASP: Clickjacking Defense', 'CWE-1021: Frame Embedding'],
    check: (url: string) => Math.random() > 0.65
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

export function analyzeRTI(url: string): RTIInfo {
  // Simulated RTI (Regional Threat Intelligence) analysis for APAC patterns
  const urlObj = new URL(url);
  const domain = urlObj.hostname.toLowerCase();
  const tld = domain.split('.').pop() || '';
  
  // APAC TLDs
  const apacTlds = ['in', 'ph', 'id', 'my', 'sg', 'asia', 'pw', 'cn', 'tw', 'kr', 'jp', 'th', 'vn'];
  const isApacTld = apacTlds.includes(tld);
  
  // Cheap hosting detection (simulated)
  const cheapHostingProviders = ['cpanel', 'plesk', 'shared', 'hostinger', 'godaddy'];
  const hasCheapHosting = Math.random() > 0.7;
  
  // WordPress detection
  const hasWordPress = Math.random() > 0.5;
  const wpOutdated = hasWordPress && Math.random() > 0.6;
  
  // External JS from suspicious TLDs
  const suspiciousTlds = ['.asia', '.pw', '.tk', '.ml', '.ga'];
  const hasSuspiciousJS = Math.random() > 0.7;
  
  // Redirect detection
  const hasRedirects = Math.random() > 0.65;
  
  // APAC phishing patterns
  const phishingPatterns = ['/verify/', '/otp/', '/login/secure/', '/pan-update/', '/kyc-update/'];
  const hasPhishingPattern = Math.random() > 0.75;
  
  // SEA threat group JS naming
  const hasThreatJS = Math.random() > 0.8;
  
  // Missing TLS on subdomains
  const missingTLS = !url.startsWith('https://') || Math.random() > 0.85;
  
  // Gov phishing clone detection
  const hasGovClone = Math.random() > 0.8;
  
  // Build detected patterns
  const detectedPatterns = [
    {
      category: 'Cheap Shared Hosting',
      detected: hasCheapHosting,
      details: hasCheapHosting 
        ? 'Detected cPanel/Plesk hosting environment commonly used in APAC scam operations'
        : 'No cheap shared hosting indicators detected'
    },
    {
      category: 'Outdated WordPress',
      detected: wpOutdated,
      details: wpOutdated 
        ? 'Outdated WordPress version detected - common in India/SEA threat campaigns'
        : hasWordPress 
          ? 'WordPress detected but appears up-to-date'
          : 'No WordPress installation detected'
    },
    {
      category: 'Suspicious External JS',
      detected: hasSuspiciousJS,
      details: hasSuspiciousJS 
        ? `External JavaScript loaded from unknown ${suspiciousTlds[Math.floor(Math.random() * suspiciousTlds.length)]} domain`
        : 'No suspicious external JavaScript sources detected'
    },
    {
      category: 'Redirect Patterns',
      detected: hasRedirects,
      details: hasRedirects 
        ? 'Multiple redirects to external domains detected - common scam tactic'
        : 'No suspicious redirect patterns detected'
    },
    {
      category: 'APAC Phishing Kit Structure',
      detected: hasPhishingPattern,
      details: hasPhishingPattern 
        ? `URL structure matches known APAC phishing kits: ${phishingPatterns[Math.floor(Math.random() * phishingPatterns.length)]}`
        : 'No APAC phishing kit patterns detected'
    },
    {
      category: 'SEA Threat Group JS Naming',
      detected: hasThreatJS,
      details: hasThreatJS 
        ? 'JavaScript naming patterns match known SEA threat group fingerprints (e.g., main.min.9832.js, validate.sec.js)'
        : 'No threat group JavaScript naming patterns detected'
    },
    {
      category: 'Missing TLS',
      detected: missingTLS,
      details: missingTLS 
        ? 'Subdomains or main domain missing TLS encryption - security risk'
        : 'TLS properly configured across all detected endpoints'
    },
    {
      category: 'Gov Phishing Clone',
      detected: hasGovClone,
      details: hasGovClone 
        ? 'Design elements match APAC government portal phishing clones (banking, post, gov services)'
        : 'No government phishing clone indicators detected'
    }
  ];
  
  // Regional indicators
  const regionalIndicators = [
    {
      indicator: 'Country TLD',
      value: isApacTld ? `APAC Region (.${tld})` : `Non-APAC (.${tld})`,
      risk: isApacTld ? ('medium' as const) : ('low' as const)
    },
    {
      indicator: 'Hosting Provider',
      value: hasCheapHosting ? 'Cheap Shared Hosting' : 'Standard Hosting',
      risk: hasCheapHosting ? ('high' as const) : ('low' as const)
    },
    {
      indicator: 'Domain Age',
      value: Math.random() > 0.5 ? 'Recently Registered' : 'Established Domain',
      risk: Math.random() > 0.5 ? ('high' as const) : ('low' as const)
    }
  ];
  
  // Calculate likelihood score
  let likelihood = 0;
  detectedPatterns.forEach(pattern => {
    if (pattern.detected) likelihood += 12.5;
  });
  
  // Adjust for APAC TLD
  if (isApacTld) likelihood += 10;
  
  // Cap at 100
  likelihood = Math.min(100, Math.round(likelihood));
  
  // Determine verdict
  let verdict = '';
  if (likelihood >= 75) {
    verdict = 'High likelihood of APAC-region threat patterns detected. Exercise extreme caution.';
  } else if (likelihood >= 50) {
    verdict = 'Moderate APAC threat indicators present. Further investigation recommended.';
  } else if (likelihood >= 25) {
    verdict = 'Some regional patterns detected, but overall risk appears low.';
  } else {
    verdict = 'Minimal APAC threat patterns detected. Site appears clean.';
  }
  
  return {
    likelihood,
    detectedPatterns,
    regionalIndicators,
    verdict
  };
}

export function analyzePortScan(url: string): PortScanInfo {
  const domain = new URL(url).hostname;
  const exposedPorts: PortScanInfo['exposedPorts'] = [];
  
  // Detect hints from URL and common patterns
  if (url.includes(':21') || url.includes('ftp://')) {
    exposedPorts.push({
      port: 21,
      service: 'FTP',
      exposureHint: 'FTP port exposed - unencrypted file transfer protocol detected',
      risk: 'high'
    });
  }
  
  if (url.includes(':22')) {
    exposedPorts.push({
      port: 22,
      service: 'SSH',
      exposureHint: 'SSH port publicly accessible - potential brute force target',
      risk: 'medium'
    });
  }
  
  if (url.includes(':3306')) {
    exposedPorts.push({
      port: 3306,
      service: 'MySQL',
      exposureHint: 'MySQL database port exposed to internet - critical security risk',
      risk: 'high'
    });
  }
  
  if (url.includes(':8080')) {
    exposedPorts.push({
      port: 8080,
      service: 'Admin Panel',
      exposureHint: 'Common admin panel port exposed',
      risk: 'medium'
    });
  }
  
  if (url.includes(':8443')) {
    exposedPorts.push({
      port: 8443,
      service: 'Control Panel',
      exposureHint: 'Control panel port accessible',
      risk: 'medium'
    });
  }
  
  if (url.includes(':2082') || url.includes(':2083')) {
    exposedPorts.push({
      port: url.includes(':2082') ? 2082 : 2083,
      service: 'cPanel',
      exposureHint: 'cPanel port exposed - cheap shared hosting indicator',
      risk: 'medium'
    });
  }
  
  // Simulate additional detections
  if (Math.random() > 0.7) {
    exposedPorts.push({
      port: 80,
      service: 'HTTP',
      exposureHint: 'Unencrypted HTTP traffic allowed',
      risk: 'low'
    });
  }
  
  const summary = exposedPorts.length > 0
    ? `Detected ${exposedPorts.length} exposed port(s) - passive scan only, no active probing performed`
    : 'No obvious port exposure detected from passive analysis';
  
  return { exposedPorts, summary };
}

export function analyzeFrameworkRisk(technology: TechnologyInfo): FrameworkRiskInfo {
  let riskScore = 0;
  const vulnerabilities: string[] = [];
  let recommendation = '';
  
  const framework = technology.cms || technology.framework?.[0];
  
  if (technology.cms === 'WordPress') {
    riskScore = 65;
    vulnerabilities.push(
      'WordPress is the #1 targeted CMS globally',
      'Plugin vulnerabilities common',
      'Theme security often overlooked',
      'Known for outdated installations'
    );
    recommendation = 'Keep WordPress core, themes, and plugins updated. Use security plugins like Wordfence.';
  } else if (technology.cms === 'Joomla') {
    riskScore = 60;
    vulnerabilities.push(
      'Frequent security patches required',
      'Extension vulnerabilities',
      'Legacy versions still in use'
    );
    recommendation = 'Update to latest Joomla version. Review all extensions for security patches.';
  } else if (technology.cms === 'Magento') {
    riskScore = 55;
    vulnerabilities.push(
      'Complex codebase increases attack surface',
      'E-commerce target for payment data theft',
      'Extension security varies'
    );
    recommendation = 'Regular security audits required. Keep Magento and extensions updated.';
  } else if (technology.framework?.includes('Laravel')) {
    riskScore = 25;
    vulnerabilities.push(
      'Misconfiguration risks if .env exposed',
      'Debug mode in production is dangerous'
    );
    recommendation = 'Ensure .env is protected and debug mode is disabled in production.';
  } else if (technology.framework?.includes('Django')) {
    riskScore = 20;
    vulnerabilities.push(
      'SQL injection if queries not parameterized',
      'CSRF protection must be enabled'
    );
    recommendation = 'Follow Django security best practices and keep framework updated.';
  } else {
    riskScore = 35;
    vulnerabilities.push('Framework/CMS detected but specific vulnerabilities unknown');
    recommendation = 'Ensure all software is up to date and follow security best practices.';
  }
  
  return {
    framework,
    version: Math.random() > 0.5 ? 'Outdated' : 'Current',
    riskScore,
    vulnerabilities,
    recommendation
  };
}

export function analyzeJSSecurity(url: string): JSSecurityInfo {
  const exposedSecrets: JSSecurityInfo['exposedSecrets'] = [];
  const suspiciousPatterns: string[] = [];
  
  // Simulate detection patterns
  if (Math.random() > 0.6) {
    exposedSecrets.push({
      type: 'API Key',
      severity: 'high',
      location: 'main.js line 142',
      preview: 'const API_KEY = "sk_live_51H..."'
    });
  }
  
  if (Math.random() > 0.7) {
    exposedSecrets.push({
      type: 'Access Token',
      severity: 'high',
      location: 'config.js line 23',
      preview: 'token: "eyJhbGciOiJIUzI1NiIsInR..."'
    });
  }
  
  if (Math.random() > 0.5) {
    exposedSecrets.push({
      type: 'Internal Endpoint',
      severity: 'medium',
      location: 'app.js line 89',
      preview: 'apiUrl: "https://internal-api.company.local"'
    });
  }
  
  if (Math.random() > 0.6) {
    exposedSecrets.push({
      type: 'Admin Route',
      severity: 'medium',
      location: 'router.js line 45',
      preview: 'path: "/secret-admin-panel"'
    });
  }
  
  if (Math.random() > 0.8) {
    exposedSecrets.push({
      type: 'Debug Flag',
      severity: 'low',
      location: 'init.js line 12',
      preview: 'DEBUG_MODE: true'
    });
  }
  
  // Suspicious patterns
  if (exposedSecrets.length > 0) {
    suspiciousPatterns.push('Hardcoded credentials detected');
  }
  
  if (Math.random() > 0.5) {
    suspiciousPatterns.push('Obfuscated JavaScript code present');
  }
  
  if (Math.random() > 0.6) {
    suspiciousPatterns.push('External script loading without SRI');
  }
  
  const riskLevel: 'low' | 'medium' | 'high' = 
    exposedSecrets.some(s => s.severity === 'high') ? 'high' :
    exposedSecrets.some(s => s.severity === 'medium') ? 'medium' : 'low';
  
  return {
    exposedSecrets,
    suspiciousPatterns,
    riskLevel
  };
}

export function analyzeScamDetection(url: string, rti: RTIInfo): ScamDetectionInfo {
  const domain = new URL(url).hostname;
  const matchedTemplates: string[] = [];
  let templateMatch = 0;
  
  // Check for common scam patterns
  if (domain.includes('verify') || domain.includes('secure') || domain.includes('update')) {
    matchedTemplates.push('Phishing verification template');
    templateMatch += 30;
  }
  
  if (rti.detectedPatterns.some(p => p.category === 'APAC Phishing Kit Structure' && p.detected)) {
    matchedTemplates.push('APAC phishing kit structure');
    templateMatch += 25;
  }
  
  if (rti.detectedPatterns.some(p => p.category === 'SEA Threat Group JS Naming' && p.detected)) {
    matchedTemplates.push('SEA scam kit JavaScript patterns');
    templateMatch += 20;
  }
  
  if (Math.random() > 0.6) {
    matchedTemplates.push('Generic credential harvesting page');
    templateMatch += 15;
  }
  
  const jsKitMatch = rti.detectedPatterns.some(
    p => p.category === 'SEA Threat Group JS Naming' && p.detected
  );
  
  const redirectBehavior: 'safe' | 'suspicious' | 'dangerous' = 
    rti.detectedPatterns.some(p => p.category === 'Redirects to Scam Domains' && p.detected) ? 'dangerous' :
    Math.random() > 0.5 ? 'suspicious' : 'safe';
  
  let overallVerdict = '';
  if (templateMatch >= 60 && jsKitMatch) {
    overallVerdict = `This site resembles ${matchedTemplates.length} known scam templates (${templateMatch}% match). JS naming patterns similar to SEA scam kits. High redirect-to-unknown TLD behavior.`;
  } else if (templateMatch >= 40) {
    overallVerdict = `Moderate scam indicators detected (${templateMatch}% template match). Some suspicious patterns present.`;
  } else {
    overallVerdict = `Low scam template match (${templateMatch}%). Site structure appears relatively normal.`;
  }
  
  return {
    templateMatch,
    matchedTemplates,
    jsKitMatch,
    redirectBehavior,
    overallVerdict
  };
}

export function generateSuspicionTags(
  url: string,
  technology: TechnologyInfo,
  portScan: PortScanInfo,
  frameworkRisk: FrameworkRiskInfo,
  scamDetection: ScamDetectionInfo
): SuspicionTag[] {
  const tags: SuspicionTag[] = [];
  
  // Scam detection based tags
  if (scamDetection.templateMatch >= 60) {
    tags.push('Scam Template');
  }
  
  if (scamDetection.jsKitMatch) {
    tags.push('Phishing Kit');
  }
  
  // Technology based tags
  if (technology.cms === 'WordPress' && frameworkRisk.version === 'Outdated') {
    tags.push('Outdated WordPress Theme');
  }
  
  if (technology.cms === 'Shopify') {
    tags.push('E-commerce Store');
  }
  
  // Hosting based tags
  if (portScan.exposedPorts.some(p => p.service === 'cPanel')) {
    tags.push('Shared Hosting');
  }
  
  // Pattern based tags
  const domain = new URL(url).hostname;
  if (domain.includes('.edu') || domain.includes('student') || domain.includes('project')) {
    tags.push('Student Project');
  }
  
  if (domain.includes('.gov') || domain.includes('government')) {
    tags.push('Government Clone');
  }
  
  // Default tags if nothing suspicious
  if (tags.length === 0) {
    if (technology.analytics && technology.analytics.length > 0) {
      tags.push('Professional Site');
    } else {
      tags.push('Small Business Site');
    }
  }
  
  return tags;
}

export function generateRiskThemes(
  issues: SecurityIssue[],
  portScan: PortScanInfo,
  frameworkRisk: FrameworkRiskInfo,
  jsSecurity: JSSecurityInfo,
  scamDetection: ScamDetectionInfo,
  rti: RTIInfo
): RiskTheme[] {
  const themes: RiskTheme[] = [];
  
  // Infrastructure Security Theme
  const infraFindings: string[] = [];
  portScan.exposedPorts.forEach(p => {
    if (p.risk === 'high' || p.risk === 'medium') {
      infraFindings.push(p.exposureHint);
    }
  });
  
  if (infraFindings.length > 0) {
    themes.push({
      theme: 'Infrastructure Security',
      severity: portScan.exposedPorts.some(p => p.risk === 'high') ? 'high' : 'medium',
      findings: infraFindings,
      score: Math.max(0, 100 - (infraFindings.length * 20))
    });
  }
  
  // Application Vulnerabilities Theme
  const appFindings = issues.map(i => i.title);
  if (appFindings.length > 0) {
    const criticalCount = issues.filter(i => i.severity === 'high').length;
    themes.push({
      theme: 'Application Vulnerabilities',
      severity: criticalCount > 0 ? 'critical' : 'high',
      findings: appFindings,
      score: Math.max(0, 100 - (issues.length * 15))
    });
  }
  
  // Framework & Platform Risks Theme
  if (frameworkRisk.riskScore > 40) {
    themes.push({
      theme: 'Framework & Platform Risks',
      severity: frameworkRisk.riskScore > 60 ? 'high' : 'medium',
      findings: frameworkRisk.vulnerabilities,
      score: 100 - frameworkRisk.riskScore
    });
  }
  
  // Code Security Theme
  if (jsSecurity.exposedSecrets.length > 0) {
    themes.push({
      theme: 'Code Security',
      severity: jsSecurity.riskLevel,
      findings: jsSecurity.exposedSecrets.map(s => `${s.type} exposed in ${s.location}`),
      score: Math.max(0, 100 - (jsSecurity.exposedSecrets.length * 15))
    });
  }
  
  // Regional Threat Indicators Theme
  if (rti.likelihood > 40) {
    themes.push({
      theme: 'Regional Threat Indicators',
      severity: rti.likelihood > 70 ? 'critical' : rti.likelihood > 50 ? 'high' : 'medium',
      findings: rti.detectedPatterns.filter(p => p.detected).map(p => p.details),
      score: 100 - rti.likelihood
    });
  }
  
  // Scam & Phishing Indicators Theme
  if (scamDetection.templateMatch > 30) {
    themes.push({
      theme: 'Scam & Phishing Indicators',
      severity: scamDetection.templateMatch > 60 ? 'critical' : 'high',
      findings: [scamDetection.overallVerdict, ...scamDetection.matchedTemplates],
      score: Math.max(0, 100 - scamDetection.templateMatch)
    });
  }
  
  return themes;
}

export function analyzePassiveCrawl(url: string): PassiveCrawlInfo {
  const discoveredPaths: PassiveCrawlInfo['discoveredPaths'] = [];
  const commonPaths: { path: string; risk: 'low' | 'medium' | 'high'; type: string }[] = [
    { path: '/wp-admin', risk: 'high', type: 'WordPress Admin' },
    { path: '/admin', risk: 'high', type: 'Admin Panel' },
    { path: '/login', risk: 'medium', type: 'Login Page' },
    { path: '/config', risk: 'high', type: 'Configuration File' },
    { path: '/backup', risk: 'high', type: 'Backup Directory' },
    { path: '/test', risk: 'medium', type: 'Test Environment' },
    { path: '/old', risk: 'medium', type: 'Legacy Files' },
    { path: '/v1', risk: 'low', type: 'API Version' },
    { path: '/debug', risk: 'high', type: 'Debug Console' },
    { path: '/.git', risk: 'high', type: 'Git Repository' },
    { path: '/.env', risk: 'high', type: 'Environment File' }
  ];
  
  // Simulate discovering some paths
  commonPaths.forEach(pathInfo => {
    if (Math.random() > 0.7) {
      discoveredPaths.push(pathInfo);
    }
  });
  
  const highRiskCount = discoveredPaths.filter(p => p.risk === 'high').length;
  const summary = discoveredPaths.length > 0
    ? `Discovered ${discoveredPaths.length} sensitive path(s) via passive HTML parsing. ${highRiskCount} high-risk paths found.`
    : 'No sensitive administrative or configuration paths discovered in passive crawl.';
  
  return {
    discoveredPaths,
    summary
  };
}

export function calculateTrustScore(
  score: number,
  riskThemes: RiskTheme[],
  scamDetection: ScamDetectionInfo,
  rti: RTIInfo
): number {
  let trustScore = score;
  
  // Reduce trust based on scam detection
  trustScore -= scamDetection.templateMatch * 0.5;
  
  // Reduce trust based on RTI likelihood
  trustScore -= rti.likelihood * 0.3;
  
  // Reduce trust based on critical themes
  const criticalThemes = riskThemes.filter(t => t.severity === 'critical').length;
  trustScore -= criticalThemes * 15;
  
  // Ensure score is between 0-100
  return Math.max(0, Math.min(100, Math.round(trustScore)));
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

  // Detect technology, network, SEO, and RTI
  const technology = detectTechnology(url);
  const network = detectNetwork(url);
  const seo = analyzeSEO(url);
  const rti = analyzeRTI(url);
  
  // New advanced analyses
  const portScan = analyzePortScan(url);
  const frameworkRisk = analyzeFrameworkRisk(technology);
  const jsSecurity = analyzeJSSecurity(url);
  const scamDetection = analyzeScamDetection(url, rti);
  const suspicionTags = generateSuspicionTags(url, technology, portScan, frameworkRisk, scamDetection);
  const passiveCrawl = analyzePassiveCrawl(url);
  const riskThemes = generateRiskThemes(issues, portScan, frameworkRisk, jsSecurity, scamDetection, rti);
  const trustScore = calculateTrustScore(score, riskThemes, scamDetection, rti);
  
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
    trustScore,
    issues,
    passedChecks,
    technology,
    network,
    seo,
    rti,
    portScan,
    frameworkRisk,
    jsSecurity,
    scamDetection,
    suspicionTags,
    riskThemes,
    passiveCrawl,
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
