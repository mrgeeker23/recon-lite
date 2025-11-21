// Active HTTP Scanner - Makes real requests to gather data
// CORS limitations: Can only scan CORS-enabled endpoints or use CORS proxies

export interface HeaderAnalysis {
  securityHeaders: {
    name: string;
    present: boolean;
    value?: string;
    risk: 'low' | 'medium' | 'high';
    recommendation?: string;
  }[];
  allHeaders: { name: string; value: string }[];
  score: number;
}

export interface EndpointDiscovery {
  endpoints: {
    path: string;
    status: number;
    responseTime: number;
    contentType?: string;
    accessible: boolean;
    risk: 'low' | 'medium' | 'high';
    details: string;
  }[];
  summary: string;
}

export interface ActiveScanResult {
  headers: HeaderAnalysis;
  endpoints: EndpointDiscovery;
  responseTime: number;
  accessible: boolean;
  errorMessage?: string;
}

const SECURITY_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    required: true,
    risk: 'high' as const,
    recommendation: 'Enable HSTS to force HTTPS connections'
  },
  {
    name: 'Content-Security-Policy',
    required: true,
    risk: 'high' as const,
    recommendation: 'Implement CSP to prevent XSS attacks'
  },
  {
    name: 'X-Frame-Options',
    required: true,
    risk: 'medium' as const,
    recommendation: 'Set X-Frame-Options to prevent clickjacking'
  },
  {
    name: 'X-Content-Type-Options',
    required: true,
    risk: 'medium' as const,
    recommendation: 'Set to "nosniff" to prevent MIME-type sniffing'
  },
  {
    name: 'Referrer-Policy',
    required: false,
    risk: 'low' as const,
    recommendation: 'Configure referrer policy for privacy'
  },
  {
    name: 'Permissions-Policy',
    required: false,
    risk: 'low' as const,
    recommendation: 'Configure permissions policy for better control'
  },
  {
    name: 'X-XSS-Protection',
    required: false,
    risk: 'low' as const,
    recommendation: 'Enable XSS protection (legacy browsers)'
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    required: false,
    risk: 'low' as const,
    recommendation: 'Configure COEP for cross-origin isolation'
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    required: false,
    risk: 'low' as const,
    recommendation: 'Configure COOP to isolate browsing contexts'
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    required: false,
    risk: 'low' as const,
    recommendation: 'Configure CORP to protect resources'
  }
];

const COMMON_ENDPOINTS = [
  // API Endpoints
  { path: '/api', type: 'API Endpoint' },
  { path: '/api/v1', type: 'API Endpoint' },
  { path: '/api/v2', type: 'API Endpoint' },
  { path: '/api/v3', type: 'API Endpoint' },
  { path: '/graphql', type: 'GraphQL Endpoint' },
  { path: '/rest', type: 'REST API' },
  { path: '/v1', type: 'API Version 1' },
  { path: '/v2', type: 'API Version 2' },
  
  // Standard Files
  { path: '/robots.txt', type: 'Robots File' },
  { path: '/sitemap.xml', type: 'Sitemap' },
  { path: '/sitemap_index.xml', type: 'Sitemap Index' },
  { path: '/.well-known/security.txt', type: 'Security Info' },
  { path: '/.well-known/openid-configuration', type: 'OpenID Config' },
  { path: '/.well-known/change-password', type: 'Password Change' },
  
  // Admin Panels & Dashboards
  { path: '/admin', type: 'Admin Panel' },
  { path: '/administrator', type: 'Administrator Panel' },
  { path: '/admin.php', type: 'Admin PHP' },
  { path: '/wp-admin', type: 'WordPress Admin' },
  { path: '/wp-login.php', type: 'WordPress Login' },
  { path: '/phpmyadmin', type: 'phpMyAdmin' },
  { path: '/cpanel', type: 'cPanel' },
  { path: '/plesk', type: 'Plesk Panel' },
  { path: '/manager', type: 'Manager Panel' },
  { path: '/controlpanel', type: 'Control Panel' },
  
  // Authentication Pages
  { path: '/login', type: 'Login Page' },
  { path: '/signin', type: 'Sign In Page' },
  { path: '/signup', type: 'Sign Up Page' },
  { path: '/register', type: 'Registration Page' },
  { path: '/auth', type: 'Auth Endpoint' },
  { path: '/authentication', type: 'Authentication' },
  { path: '/oauth', type: 'OAuth Endpoint' },
  
  // Application Pages
  { path: '/dashboard', type: 'Dashboard' },
  { path: '/console', type: 'Console' },
  { path: '/portal', type: 'Portal' },
  { path: '/app', type: 'Application' },
  
  // Configuration Files (High Risk)
  { path: '/config.json', type: 'Config File' },
  { path: '/config.php', type: 'PHP Config' },
  { path: '/configuration.php', type: 'Configuration' },
  { path: '/settings.json', type: 'Settings File' },
  { path: '/app.json', type: 'App Config' },
  { path: '/web.config', type: 'Web Config' },
  { path: '/.htaccess', type: 'Apache Config' },
  { path: '/composer.json', type: 'Composer Config' },
  { path: '/package.json', type: 'Package Info' },
  { path: '/package-lock.json', type: 'Package Lock' },
  { path: '/yarn.lock', type: 'Yarn Lock' },
  
  // Environment Files (Critical Risk)
  { path: '/.env', type: 'Environment File' },
  { path: '/.env.local', type: 'Local Env File' },
  { path: '/.env.production', type: 'Production Env' },
  { path: '/.env.development', type: 'Dev Env File' },
  { path: '/.env.example', type: 'Example Env' },
  { path: '/.env.backup', type: 'Backup Env' },
  
  // Version Control (Critical Risk)
  { path: '/.git', type: 'Git Repository' },
  { path: '/.git/config', type: 'Git Config' },
  { path: '/.git/HEAD', type: 'Git HEAD' },
  { path: '/.gitignore', type: 'Git Ignore' },
  { path: '/.svn', type: 'SVN Repository' },
  { path: '/.svn/entries', type: 'SVN Entries' },
  { path: '/.hg', type: 'Mercurial Repo' },
  
  // Backup Files (High Risk)
  { path: '/backup', type: 'Backup Directory' },
  { path: '/backup.zip', type: 'Backup Archive' },
  { path: '/backup.tar.gz', type: 'Backup Tarball' },
  { path: '/backup.sql', type: 'SQL Backup' },
  { path: '/database.sql', type: 'Database Dump' },
  { path: '/db.sql', type: 'DB Dump' },
  { path: '/dump.sql', type: 'SQL Dump' },
  { path: '/site-backup.zip', type: 'Site Backup' },
  { path: '/www.zip', type: 'WWW Archive' },
  { path: '/web.zip', type: 'Web Archive' },
  
  // Log Files (Medium Risk)
  { path: '/logs', type: 'Log Directory' },
  { path: '/log', type: 'Log Folder' },
  { path: '/error.log', type: 'Error Log' },
  { path: '/access.log', type: 'Access Log' },
  { path: '/debug.log', type: 'Debug Log' },
  { path: '/application.log', type: 'App Log' },
  
  // Documentation & API Docs
  { path: '/swagger', type: 'Swagger API Docs' },
  { path: '/swagger-ui', type: 'Swagger UI' },
  { path: '/swagger.json', type: 'Swagger JSON' },
  { path: '/api-docs', type: 'API Documentation' },
  { path: '/docs', type: 'Documentation' },
  { path: '/documentation', type: 'Docs Page' },
  { path: '/api/docs', type: 'API Docs' },
  { path: '/redoc', type: 'ReDoc API' },
  
  // Monitoring & Status
  { path: '/health', type: 'Health Check' },
  { path: '/healthz', type: 'Health Check' },
  { path: '/status', type: 'Status Page' },
  { path: '/metrics', type: 'Metrics Endpoint' },
  { path: '/ping', type: 'Ping Endpoint' },
  { path: '/ready', type: 'Readiness Check' },
  { path: '/live', type: 'Liveness Check' },
  
  // Debug & Test Endpoints
  { path: '/debug', type: 'Debug Endpoint' },
  { path: '/test', type: 'Test Page' },
  { path: '/phpinfo.php', type: 'PHP Info' },
  { path: '/info.php', type: 'Info Page' },
  { path: '/server-status', type: 'Server Status' },
  { path: '/server-info', type: 'Server Info' },
  
  // Upload Directories
  { path: '/uploads', type: 'Uploads Folder' },
  { path: '/upload', type: 'Upload Directory' },
  { path: '/files', type: 'Files Directory' },
  { path: '/media', type: 'Media Folder' },
  { path: '/assets', type: 'Assets Folder' },
  { path: '/static', type: 'Static Files' },
  { path: '/public', type: 'Public Directory' },
  
  // Common CMS Paths
  { path: '/wp-content', type: 'WordPress Content' },
  { path: '/wp-includes', type: 'WordPress Includes' },
  { path: '/wp-json', type: 'WordPress REST API' },
  { path: '/xmlrpc.php', type: 'XML-RPC' },
  { path: '/readme.html', type: 'WordPress Readme' },
  { path: '/license.txt', type: 'License File' },
  
  // Database Interfaces
  { path: '/adminer', type: 'Adminer DB Tool' },
  { path: '/adminer.php', type: 'Adminer' },
  { path: '/db', type: 'Database Interface' },
  { path: '/database', type: 'Database Panel' },
  
  // IDE & Editor Configs
  { path: '/.vscode', type: 'VS Code Config' },
  { path: '/.idea', type: 'IntelliJ Config' },
  { path: '/.DS_Store', type: 'macOS System File' },
];

// CORS proxy for testing (optional, can be removed if direct access works)
const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

async function fetchWithTimeout(url: string, timeout = 5000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, { 
      signal: controller.signal,
      mode: 'cors',
      cache: 'no-cache'
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

export async function analyzeHeaders(url: string): Promise<HeaderAnalysis> {
  const startTime = performance.now();
  
  try {
    // Try direct fetch first
    let response: Response;
    try {
      response = await fetchWithTimeout(url, 5000);
    } catch (directError) {
      // If direct fetch fails due to CORS, try with proxy
      console.log('Direct fetch failed, trying CORS proxy');
      response = await fetchWithTimeout(CORS_PROXY + encodeURIComponent(url), 5000);
    }
    
    const endTime = performance.now();
    const responseTime = Math.round(endTime - startTime);
    
    // Extract all headers
    const allHeaders: { name: string; value: string }[] = [];
    response.headers.forEach((value, name) => {
      allHeaders.push({ name, value });
    });
    
    // Analyze security headers
    let score = 100;
    const securityHeaders = SECURITY_HEADERS.map(header => {
      const value = response.headers.get(header.name);
      const present = !!value;
      
      if (!present && header.required) {
        score -= header.risk === 'high' ? 20 : header.risk === 'medium' ? 10 : 5;
      }
      
      return {
        name: header.name,
        present,
        value: value || undefined,
        risk: present ? ('low' as const) : header.risk,
        recommendation: present ? undefined : header.recommendation
      };
    });
    
    return {
      securityHeaders,
      allHeaders,
      score: Math.max(0, score)
    };
  } catch (error) {
    console.error('Header analysis failed:', error);
    
    // Return simulated data if real fetch fails
    return {
      securityHeaders: SECURITY_HEADERS.map(h => ({
        name: h.name,
        present: false,
        risk: h.risk,
        recommendation: h.recommendation
      })),
      allHeaders: [],
      score: 0
    };
  }
}

export async function discoverEndpoints(baseUrl: string): Promise<EndpointDiscovery> {
  const results = await Promise.allSettled(
    COMMON_ENDPOINTS.map(async (endpoint) => {
      const fullUrl = new URL(endpoint.path, baseUrl).toString();
      const startTime = performance.now();
      
      try {
        let response: Response;
        try {
          response = await fetchWithTimeout(fullUrl, 3000);
        } catch {
          // Try with CORS proxy
          response = await fetchWithTimeout(CORS_PROXY + encodeURIComponent(fullUrl), 3000);
        }
        
        const endTime = performance.now();
        const responseTime = Math.round(endTime - startTime);
        const contentType = response.headers.get('content-type') || undefined;
        
        // Determine risk level based on endpoint type and path
        let risk: 'low' | 'medium' | 'high' = 'low';
        let details = `${endpoint.type} found`;
        
        // Critical Risk - Exposed sensitive files
        if (endpoint.path.includes('.env') || 
            endpoint.path.includes('.git') || 
            endpoint.path.includes('.svn') ||
            endpoint.path.includes('backup.sql') ||
            endpoint.path.includes('database.sql') ||
            endpoint.path.includes('dump.sql')) {
          risk = 'high';
          details = '🚨 CRITICAL: Sensitive file exposed! Immediate action required.';
        }
        // High Risk - Admin panels, configs, backups
        else if (endpoint.path.includes('admin') || 
                 endpoint.path.includes('phpmyadmin') ||
                 endpoint.path.includes('cpanel') ||
                 endpoint.path.includes('config.php') ||
                 endpoint.path.includes('web.config') ||
                 endpoint.path.includes('backup') ||
                 endpoint.path.includes('.zip') ||
                 endpoint.path.includes('phpinfo')) {
          risk = 'high';
          details = '⚠️ High risk: Sensitive endpoint publicly accessible';
        }
        // Medium Risk - Login pages, debug endpoints, logs
        else if (endpoint.path.includes('login') ||
                 endpoint.path.includes('signin') ||
                 endpoint.path.includes('debug') ||
                 endpoint.path.includes('test') ||
                 endpoint.path.includes('log') ||
                 endpoint.path.includes('swagger') ||
                 endpoint.path.includes('metrics')) {
          risk = 'medium';
          details = '⚡ Medium risk: Consider restricting access';
        }
        // Low Risk - Public endpoints
        else if (response.status === 200) {
          details = `✓ ${endpoint.type} accessible (${response.status})`;
        }
        
        return {
          path: endpoint.path,
          status: response.status,
          responseTime,
          contentType,
          accessible: response.status >= 200 && response.status < 400,
          risk,
          details
        };
      } catch (error) {
        return {
          path: endpoint.path,
          status: 0,
          responseTime: 0,
          accessible: false,
          risk: 'low' as const,
          details: 'Not accessible or blocked by CORS'
        };
      }
    })
  );
  
  const endpoints = results
    .filter((r): r is PromiseFulfilledResult<any> => r.status === 'fulfilled')
    .map(r => r.value)
    .filter(e => e.accessible);
  
  const accessibleCount = endpoints.length;
  const highRiskCount = endpoints.filter(e => e.risk === 'high').length;
  const mediumRiskCount = endpoints.filter(e => e.risk === 'medium').length;
  
  let summary = `Discovered ${accessibleCount} accessible endpoints`;
  if (highRiskCount > 0) {
    summary += `, ${highRiskCount} with high risk`;
  }
  if (mediumRiskCount > 0) {
    summary += `, ${mediumRiskCount} with medium risk`;
  }
  
  return {
    endpoints,
    summary
  };
}

export async function performActiveScan(url: string): Promise<ActiveScanResult> {
  const startTime = performance.now();
  
  try {
    // Run both analyses in parallel
    const [headers, endpoints] = await Promise.all([
      analyzeHeaders(url),
      discoverEndpoints(url)
    ]);
    
    const endTime = performance.now();
    const responseTime = Math.round(endTime - startTime);
    
    return {
      headers,
      endpoints,
      responseTime,
      accessible: true
    };
  } catch (error) {
    return {
      headers: {
        securityHeaders: [],
        allHeaders: [],
        score: 0
      },
      endpoints: {
        endpoints: [],
        summary: 'Unable to perform endpoint discovery'
      },
      responseTime: 0,
      accessible: false,
      errorMessage: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}
