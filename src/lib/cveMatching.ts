// CVE Version Matching System
// Detects technology versions and matches against known CVEs

export interface CVEMatch {
  cveId: string;
  technology: string;
  version: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  cvssScore: number;
  publishedDate: string;
  url: string;
}

export interface TechnologyVersion {
  name: string;
  version: string;
  detectedFrom: string;
}

// Known CVEs database (expandable)
const KNOWN_CVES: Record<string, CVEMatch[]> = {
  'jQuery': [
    {
      cveId: 'CVE-2020-11022',
      technology: 'jQuery',
      version: '< 3.5.0',
      severity: 'medium',
      description: 'Cross-Site Scripting (XSS) vulnerability in jQuery allows attackers to execute arbitrary JavaScript.',
      cvssScore: 6.1,
      publishedDate: '2020-04-29',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022'
    },
    {
      cveId: 'CVE-2020-11023',
      technology: 'jQuery',
      version: '< 3.5.0',
      severity: 'medium',
      description: 'Prototype pollution vulnerability in jQuery that could lead to denial of service.',
      cvssScore: 6.1,
      publishedDate: '2020-04-29',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11023'
    },
    {
      cveId: 'CVE-2019-11358',
      technology: 'jQuery',
      version: '< 3.4.0',
      severity: 'medium',
      description: 'Prototype pollution vulnerability in jQuery.extend function.',
      cvssScore: 6.1,
      publishedDate: '2019-04-20',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358'
    }
  ],
  'Bootstrap': [
    {
      cveId: 'CVE-2019-8331',
      technology: 'Bootstrap',
      version: '< 4.3.1',
      severity: 'medium',
      description: 'XSS vulnerability in data-target attribute of scrollspy component.',
      cvssScore: 6.1,
      publishedDate: '2019-02-20',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331'
    },
    {
      cveId: 'CVE-2018-14042',
      technology: 'Bootstrap',
      version: '< 4.1.2',
      severity: 'medium',
      description: 'XSS vulnerability in Collapse component when using data-parent attribute.',
      cvssScore: 6.1,
      publishedDate: '2018-07-13',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-14042'
    }
  ],
  'Angular': [
    {
      cveId: 'CVE-2020-7676',
      technology: 'Angular',
      version: '< 9.1.13',
      severity: 'high',
      description: 'XSS vulnerability in angular expressions that could allow code execution.',
      cvssScore: 7.5,
      publishedDate: '2020-06-08',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2020-7676'
    }
  ],
  'React': [
    {
      cveId: 'CVE-2018-6341',
      technology: 'React',
      version: '< 16.4.2',
      severity: 'medium',
      description: 'Potential XSS vulnerability when rendering user input with dangerouslySetInnerHTML.',
      cvssScore: 6.1,
      publishedDate: '2018-08-17',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-6341'
    }
  ],
  'WordPress': [
    {
      cveId: 'CVE-2023-2745',
      technology: 'WordPress',
      version: '< 6.2.1',
      severity: 'high',
      description: 'SQL Injection vulnerability in WordPress core allows unauthenticated attackers to expose sensitive information.',
      cvssScore: 7.5,
      publishedDate: '2023-05-16',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-2745'
    }
  ],
  'Apache': [
    {
      cveId: 'CVE-2021-44228',
      technology: 'Apache Log4j',
      version: '< 2.17.0',
      severity: 'critical',
      description: 'Remote code execution vulnerability in Log4j (Log4Shell).',
      cvssScore: 10.0,
      publishedDate: '2021-12-10',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228'
    }
  ],
  'nginx': [
    {
      cveId: 'CVE-2021-23017',
      technology: 'nginx',
      version: '< 1.20.1',
      severity: 'high',
      description: 'Off-by-one error in nginx resolver that could lead to memory corruption.',
      cvssScore: 7.7,
      publishedDate: '2021-06-01',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
    }
  ],
  'Express': [
    {
      cveId: 'CVE-2022-24999',
      technology: 'Express.js',
      version: '< 4.17.3',
      severity: 'medium',
      description: 'Open redirect vulnerability in Express res.redirect() function.',
      cvssScore: 6.1,
      publishedDate: '2022-11-26',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-24999'
    }
  ]
};

export function detectVersionsFromHeaders(headers: { name: string; value: string }[]): TechnologyVersion[] {
  const versions: TechnologyVersion[] = [];
  
  for (const header of headers) {
    // Detect server versions
    if (header.name.toLowerCase() === 'server') {
      const serverMatch = header.value.match(/([a-zA-Z]+)\/([0-9.]+)/);
      if (serverMatch) {
        versions.push({
          name: serverMatch[1],
          version: serverMatch[2],
          detectedFrom: `Server header: ${header.value}`
        });
      }
    }
    
    // Detect X-Powered-By
    if (header.name.toLowerCase() === 'x-powered-by') {
      const poweredMatch = header.value.match(/([a-zA-Z]+)\/([0-9.]+)/);
      if (poweredMatch) {
        versions.push({
          name: poweredMatch[1],
          version: poweredMatch[2],
          detectedFrom: `X-Powered-By header: ${header.value}`
        });
      }
    }
    
    // Detect framework-specific headers
    if (header.name.toLowerCase() === 'x-aspnet-version') {
      versions.push({
        name: 'ASP.NET',
        version: header.value,
        detectedFrom: 'X-AspNet-Version header'
      });
    }
  }
  
  return versions;
}

export function detectVersionsFromContent(html: string): TechnologyVersion[] {
  const versions: TechnologyVersion[] = [];
  
  // Detect jQuery versions
  const jqueryMatch = html.match(/jquery[.-]([0-9.]+)(?:\.min)?\.js/i);
  if (jqueryMatch) {
    versions.push({
      name: 'jQuery',
      version: jqueryMatch[1],
      detectedFrom: 'Script tag in HTML'
    });
  }
  
  // Detect Bootstrap
  const bootstrapMatch = html.match(/bootstrap[.-]([0-9.]+)(?:\.min)?\.(?:js|css)/i);
  if (bootstrapMatch) {
    versions.push({
      name: 'Bootstrap',
      version: bootstrapMatch[1],
      detectedFrom: 'Resource reference in HTML'
    });
  }
  
  // Detect Angular
  if (html.includes('ng-version')) {
    const angularMatch = html.match(/ng-version="([0-9.]+)"/);
    if (angularMatch) {
      versions.push({
        name: 'Angular',
        version: angularMatch[1],
        detectedFrom: 'ng-version attribute'
      });
    }
  }
  
  // Detect React
  const reactMatch = html.match(/react(?:\.production)?[.-]([0-9.]+)(?:\.min)?\.js/i);
  if (reactMatch) {
    versions.push({
      name: 'React',
      version: reactMatch[1],
      detectedFrom: 'React script tag'
    });
  }
  
  // Detect WordPress
  const wpMatch = html.match(/wp-(?:content|includes).*?ver=([0-9.]+)/i);
  if (wpMatch) {
    versions.push({
      name: 'WordPress',
      version: wpMatch[1],
      detectedFrom: 'WordPress resource versioning'
    });
  }
  
  return versions;
}

function compareVersions(version: string, targetVersion: string): boolean {
  // Simple version comparison (major.minor.patch)
  const v1Parts = version.split('.').map(Number);
  const v2Parts = targetVersion.replace('<', '').trim().split('.').map(Number);
  
  for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
    const v1 = v1Parts[i] || 0;
    const v2 = v2Parts[i] || 0;
    
    if (v1 < v2) return true;
    if (v1 > v2) return false;
  }
  
  return false;
}

export function matchCVEs(detectedVersions: TechnologyVersion[]): CVEMatch[] {
  const matches: CVEMatch[] = [];
  
  for (const detected of detectedVersions) {
    const cves = KNOWN_CVES[detected.name];
    if (!cves) continue;
    
    for (const cve of cves) {
      if (compareVersions(detected.version, cve.version)) {
        matches.push({
          ...cve,
          technology: `${detected.name} ${detected.version}`
        });
      }
    }
  }
  
  return matches;
}

export async function performCVEAnalysis(
  headers: { name: string; value: string }[],
  htmlContent?: string
): Promise<{ versions: TechnologyVersion[]; cves: CVEMatch[] }> {
  // Detect versions from headers
  const versionsFromHeaders = detectVersionsFromHeaders(headers);
  
  // Detect versions from HTML if available
  const versionsFromContent = htmlContent ? detectVersionsFromContent(htmlContent) : [];
  
  // Combine and deduplicate
  const allVersions = [...versionsFromHeaders, ...versionsFromContent];
  const uniqueVersions = allVersions.filter(
    (v, i, arr) => arr.findIndex(t => t.name === v.name && t.version === v.version) === i
  );
  
  // Match CVEs
  const cveMatches = matchCVEs(uniqueVersions);
  
  return {
    versions: uniqueVersions,
    cves: cveMatches
  };
}
