// Supply Chain Security Analyzer
// Detects front-end dependencies from HTML, generates SBOM, flags outdated/vulnerable packages

export interface DetectedDependency {
  name: string;
  version: string;
  source: string; // CDN URL or detection method
  license?: string;
  status: 'current' | 'outdated' | 'vulnerable' | 'eol' | 'unknown';
  risk: 'low' | 'medium' | 'high' | 'critical';
  latestVersion?: string;
  vulnerabilities?: string[];
}

export interface SBOMEntry {
  packageName: string;
  version: string;
  source: string;
  license: string;
  status: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  notes: string;
}

export interface SupplyChainResult {
  dependencies: DetectedDependency[];
  sbom: SBOMEntry[];
  summary: {
    totalDependencies: number;
    vulnerableCount: number;
    outdatedCount: number;
    eolCount: number;
    currentCount: number;
    unknownCount: number;
    overallRisk: 'low' | 'medium' | 'high' | 'critical';
  };
}

// Known library database with latest versions and vulnerability info
const LIBRARY_DATABASE: Record<string, {
  latestVersion: string;
  eol?: boolean;
  license: string;
  vulnerableBelow?: string;
  knownVulnerabilities?: string[];
}> = {
  'jquery': {
    latestVersion: '3.7.1',
    license: 'MIT',
    vulnerableBelow: '3.5.0',
    knownVulnerabilities: ['CVE-2020-11022 (XSS)', 'CVE-2020-11023 (Prototype Pollution)', 'CVE-2019-11358 (Prototype Pollution)']
  },
  'bootstrap': {
    latestVersion: '5.3.3',
    license: 'MIT',
    vulnerableBelow: '4.3.1',
    knownVulnerabilities: ['CVE-2019-8331 (XSS in scrollspy)', 'CVE-2018-14042 (XSS in Collapse)']
  },
  'angular': {
    latestVersion: '17.3.0',
    license: 'MIT',
    vulnerableBelow: '9.1.13',
    knownVulnerabilities: ['CVE-2020-7676 (XSS in expressions)']
  },
  'angularjs': {
    latestVersion: '1.8.3',
    eol: true,
    license: 'MIT',
    vulnerableBelow: '1.8.0',
    knownVulnerabilities: ['Multiple XSS vulnerabilities', 'Prototype pollution']
  },
  'react': {
    latestVersion: '18.2.0',
    license: 'MIT',
    vulnerableBelow: '16.4.2',
    knownVulnerabilities: ['CVE-2018-6341 (XSS via dangerouslySetInnerHTML)']
  },
  'vue': {
    latestVersion: '3.4.21',
    license: 'MIT',
    vulnerableBelow: '2.5.0',
    knownVulnerabilities: ['CVE-2018-11235 (Template injection)']
  },
  'lodash': {
    latestVersion: '4.17.21',
    license: 'MIT',
    vulnerableBelow: '4.17.21',
    knownVulnerabilities: ['CVE-2021-23337 (Command Injection)', 'CVE-2020-28500 (ReDoS)', 'CVE-2019-10744 (Prototype Pollution)']
  },
  'moment': {
    latestVersion: '2.30.1',
    eol: true,
    license: 'MIT',
    knownVulnerabilities: ['CVE-2022-31129 (ReDoS)', 'Project in maintenance mode - use dayjs/date-fns']
  },
  'underscore': {
    latestVersion: '1.13.6',
    license: 'MIT',
    vulnerableBelow: '1.13.6',
    knownVulnerabilities: ['CVE-2021-25949 (Arbitrary Code Execution)']
  },
  'backbone': {
    latestVersion: '1.6.0',
    license: 'MIT'
  },
  'd3': {
    latestVersion: '7.9.0',
    license: 'ISC'
  },
  'chart.js': {
    latestVersion: '4.4.2',
    license: 'MIT'
  },
  'axios': {
    latestVersion: '1.6.8',
    license: 'MIT',
    vulnerableBelow: '1.6.0',
    knownVulnerabilities: ['CVE-2023-45857 (CSRF token leak)']
  },
  'ember': {
    latestVersion: '5.7.0',
    license: 'MIT'
  },
  'knockout': {
    latestVersion: '3.5.1',
    license: 'MIT'
  },
  'handlebars': {
    latestVersion: '4.7.8',
    license: 'MIT',
    vulnerableBelow: '4.7.7',
    knownVulnerabilities: ['CVE-2021-23369 (RCE)', 'CVE-2019-19919 (Prototype Pollution)']
  },
  'socket.io': {
    latestVersion: '4.7.5',
    license: 'MIT',
    vulnerableBelow: '4.6.2',
    knownVulnerabilities: ['CVE-2024-38355 (DoS)']
  },
  'sweetalert2': {
    latestVersion: '11.10.7',
    license: 'MIT'
  },
  'three': {
    latestVersion: '0.163.0',
    license: 'MIT'
  },
  'gsap': {
    latestVersion: '3.12.5',
    license: 'Standard GreenSock License'
  },
  'anime': {
    latestVersion: '3.2.2',
    license: 'MIT'
  },
  'popper.js': {
    latestVersion: '2.11.8',
    license: 'MIT'
  },
  'font-awesome': {
    latestVersion: '6.5.2',
    license: 'Font Awesome Free License'
  },
  'normalize.css': {
    latestVersion: '8.0.1',
    license: 'MIT'
  },
  'select2': {
    latestVersion: '4.1.0',
    license: 'MIT',
    vulnerableBelow: '4.0.13',
    knownVulnerabilities: ['CVE-2021-36741 (XSS)']
  },
  'datatables': {
    latestVersion: '2.0.3',
    license: 'MIT'
  },
  'slick': {
    latestVersion: '1.8.1',
    license: 'MIT'
  },
  'swiper': {
    latestVersion: '11.1.0',
    license: 'MIT'
  },
  'leaflet': {
    latestVersion: '1.9.4',
    license: 'BSD-2-Clause'
  },
  'modernizr': {
    latestVersion: '3.13.0',
    license: 'MIT'
  },
  'prototype': {
    latestVersion: '1.7.3',
    eol: true,
    license: 'MIT',
    knownVulnerabilities: ['Multiple XSS and injection vulnerabilities', 'Project abandoned']
  },
  'mootools': {
    latestVersion: '1.6.0',
    eol: true,
    license: 'MIT',
    knownVulnerabilities: ['Project abandoned - no security patches']
  }
};

// CDN URL patterns for dependency detection
const CDN_PATTERNS: { pattern: RegExp; nameExtractor: (match: RegExpMatchArray) => string; versionExtractor: (match: RegExpMatchArray) => string; source: string }[] = [
  // cdnjs.cloudflare.com
  {
    pattern: /cdnjs\.cloudflare\.com\/ajax\/libs\/([a-zA-Z0-9._-]+)\/([0-9.]+)/gi,
    nameExtractor: (m) => m[1],
    versionExtractor: (m) => m[2],
    source: 'cdnjs'
  },
  // jsdelivr
  {
    pattern: /cdn\.jsdelivr\.net\/(?:npm|gh)\/([a-zA-Z0-9@._-]+?)@([0-9.]+)/gi,
    nameExtractor: (m) => m[1].replace(/^@[^/]+\//, ''),
    versionExtractor: (m) => m[2],
    source: 'jsdelivr'
  },
  // unpkg
  {
    pattern: /unpkg\.com\/([a-zA-Z0-9@._-]+?)@([0-9.]+)/gi,
    nameExtractor: (m) => m[1].replace(/^@[^/]+\//, ''),
    versionExtractor: (m) => m[2],
    source: 'unpkg'
  },
  // Google APIs/CDN
  {
    pattern: /ajax\.googleapis\.com\/ajax\/libs\/([a-zA-Z0-9._-]+)\/([0-9.]+)/gi,
    nameExtractor: (m) => m[1],
    versionExtractor: (m) => m[2],
    source: 'Google CDN'
  },
  // Generic version pattern in script/link tags
  {
    pattern: /(?:src|href)=["'].*?([a-zA-Z0-9_-]+)[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:\.min)?\.(?:js|css)/gi,
    nameExtractor: (m) => m[1],
    versionExtractor: (m) => m[2],
    source: 'inline reference'
  }
];

function compareVersions(v1: string, v2: string): number {
  const parts1 = v1.split('.').map(Number);
  const parts2 = v2.split('.').map(Number);
  for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
    const a = parts1[i] || 0;
    const b = parts2[i] || 0;
    if (a < b) return -1;
    if (a > b) return 1;
  }
  return 0;
}

export function detectDependenciesFromHTML(html: string): DetectedDependency[] {
  const detected = new Map<string, DetectedDependency>();

  for (const cdnPattern of CDN_PATTERNS) {
    let match: RegExpExecArray | null;
    const regex = new RegExp(cdnPattern.pattern.source, cdnPattern.pattern.flags);
    while ((match = regex.exec(html)) !== null) {
      const rawName = cdnPattern.nameExtractor(match);
      const version = cdnPattern.versionExtractor(match);
      const normalizedName = rawName.toLowerCase().replace(/\.js$/, '').replace(/\.css$/, '');
      
      if (detected.has(normalizedName)) continue;
      
      const dbEntry = LIBRARY_DATABASE[normalizedName];
      let status: DetectedDependency['status'] = 'unknown';
      let risk: DetectedDependency['risk'] = 'low';
      let vulnerabilities: string[] | undefined;

      if (dbEntry) {
        if (dbEntry.eol) {
          status = 'eol';
          risk = 'high';
        } else if (dbEntry.vulnerableBelow && compareVersions(version, dbEntry.vulnerableBelow) < 0) {
          status = 'vulnerable';
          risk = 'critical';
          vulnerabilities = dbEntry.knownVulnerabilities;
        } else if (compareVersions(version, dbEntry.latestVersion) < 0) {
          status = 'outdated';
          risk = 'medium';
        } else {
          status = 'current';
          risk = 'low';
        }
      }

      detected.set(normalizedName, {
        name: rawName,
        version,
        source: cdnPattern.source,
        license: dbEntry?.license,
        status,
        risk,
        latestVersion: dbEntry?.latestVersion,
        vulnerabilities
      });
    }
  }

  return Array.from(detected.values());
}

export function generateSBOM(dependencies: DetectedDependency[]): SBOMEntry[] {
  return dependencies.map(dep => ({
    packageName: dep.name,
    version: dep.version,
    source: dep.source,
    license: dep.license || 'Unknown',
    status: dep.status.charAt(0).toUpperCase() + dep.status.slice(1),
    risk: dep.risk,
    notes: dep.status === 'vulnerable'
      ? `Known vulnerabilities: ${dep.vulnerabilities?.join('; ') || 'See CVE database'}`
      : dep.status === 'eol'
      ? 'End-of-life — no longer maintained or receiving security patches'
      : dep.status === 'outdated'
      ? `Update available: ${dep.latestVersion}`
      : dep.status === 'current'
      ? 'Up to date'
      : 'Version not tracked in database'
  }));
}

export function analyzeSupplyChain(html: string): SupplyChainResult {
  const dependencies = detectDependenciesFromHTML(html);
  const sbom = generateSBOM(dependencies);

  const vulnerableCount = dependencies.filter(d => d.status === 'vulnerable').length;
  const outdatedCount = dependencies.filter(d => d.status === 'outdated').length;
  const eolCount = dependencies.filter(d => d.status === 'eol').length;
  const currentCount = dependencies.filter(d => d.status === 'current').length;
  const unknownCount = dependencies.filter(d => d.status === 'unknown').length;

  let overallRisk: SupplyChainResult['summary']['overallRisk'] = 'low';
  if (vulnerableCount > 0) overallRisk = 'critical';
  else if (eolCount > 0) overallRisk = 'high';
  else if (outdatedCount > 2) overallRisk = 'medium';

  return {
    dependencies,
    sbom,
    summary: {
      totalDependencies: dependencies.length,
      vulnerableCount,
      outdatedCount,
      eolCount,
      currentCount,
      unknownCount,
      overallRisk
    }
  };
}

// Perform supply chain analysis from URL-derived content
// Since we can't always fetch HTML in-browser, also detect from URL patterns
export function analyzeSupplyChainFromURL(url: string): SupplyChainResult {
  // Simulate detection based on URL characteristics
  // In real scanning, this would use the fetched HTML
  const hostname = new URL(url).hostname;
  const dependencies: DetectedDependency[] = [];

  // Detect common patterns from URL/domain
  if (hostname.includes('wordpress') || hostname.includes('wp-')) {
    dependencies.push({
      name: 'WordPress Core',
      version: 'detected',
      source: 'URL pattern',
      status: 'unknown',
      risk: 'medium',
      license: 'GPL-2.0',
      latestVersion: '6.5.0'
    });
  }

  if (hostname.includes('shopify')) {
    dependencies.push({
      name: 'Shopify Platform',
      version: 'managed',
      source: 'Platform detection',
      status: 'current',
      risk: 'low',
      license: 'Proprietary'
    });
  }

  const sbom = generateSBOM(dependencies);

  return {
    dependencies,
    sbom,
    summary: {
      totalDependencies: dependencies.length,
      vulnerableCount: dependencies.filter(d => d.status === 'vulnerable').length,
      outdatedCount: dependencies.filter(d => d.status === 'outdated').length,
      eolCount: dependencies.filter(d => d.status === 'eol').length,
      currentCount: dependencies.filter(d => d.status === 'current').length,
      unknownCount: dependencies.filter(d => d.status === 'unknown').length,
      overallRisk: 'low'
    }
  };
}
