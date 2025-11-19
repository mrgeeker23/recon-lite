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
  { path: '/api', type: 'API Endpoint' },
  { path: '/api/v1', type: 'API Endpoint' },
  { path: '/api/v2', type: 'API Endpoint' },
  { path: '/graphql', type: 'GraphQL Endpoint' },
  { path: '/rest', type: 'REST API' },
  { path: '/robots.txt', type: 'Robots File' },
  { path: '/sitemap.xml', type: 'Sitemap' },
  { path: '/.well-known/security.txt', type: 'Security Info' },
  { path: '/.well-known/openid-configuration', type: 'OpenID Config' },
  { path: '/admin', type: 'Admin Panel' },
  { path: '/wp-admin', type: 'WordPress Admin' },
  { path: '/login', type: 'Login Page' },
  { path: '/signin', type: 'Sign In Page' },
  { path: '/dashboard', type: 'Dashboard' },
  { path: '/config.json', type: 'Config File' },
  { path: '/package.json', type: 'Package Info' },
  { path: '/.env', type: 'Environment File' },
  { path: '/.git/config', type: 'Git Config' },
  { path: '/swagger', type: 'API Docs' },
  { path: '/docs', type: 'Documentation' },
  { path: '/health', type: 'Health Check' },
  { path: '/status', type: 'Status Page' },
  { path: '/metrics', type: 'Metrics Endpoint' },
  { path: '/debug', type: 'Debug Endpoint' },
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
        
        // Determine risk level
        let risk: 'low' | 'medium' | 'high' = 'low';
        let details = `${endpoint.type} found`;
        
        if (endpoint.path.includes('.env') || endpoint.path.includes('.git')) {
          risk = 'high';
          details = 'Sensitive file exposed! This should not be publicly accessible.';
        } else if (endpoint.path.includes('admin') || endpoint.path.includes('config')) {
          risk = 'medium';
          details = 'Potentially sensitive endpoint accessible';
        } else if (response.status === 200) {
          details = `${endpoint.type} accessible (${response.status})`;
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
