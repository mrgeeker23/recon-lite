# ReconLite - Application Workflow

## System Architecture & Data Flow

```mermaid
graph TB
    Start([User Enters URLs]) --> Input[ScannerInput Component]
    Input --> Parse[Parse & Validate URLs]
    Parse --> Index[Index.tsx - Main Controller]
    
    Index --> Parallel{Parallel Scanning}
    
    Parallel --> Scanner[scanner.ts]
    Parallel --> Active[activeScanner.ts]
    
    Scanner --> SEO[SEO Analysis]
    Scanner --> Tech[Technology Detection]
    Scanner --> Network[Network Information]
    Scanner --> Security[Security Checks]
    
    Security --> Check1[Open Redirects]
    Security --> Check2[XSS Vulnerabilities]
    Security --> Check3[SQL Injection]
    Security --> Check4[Exposed Credentials]
    Security --> Check5[15+ More Checks]
    
    Active --> Headers[HTTP Header Analysis]
    Active --> Endpoints[Endpoint Discovery]
    
    Headers --> H1[HSTS]
    Headers --> H2[CSP]
    Headers --> H3[X-Frame-Options]
    Headers --> H4[10+ More Headers]
    
    Endpoints --> E1[Admin Panels]
    Endpoints --> E2[Config Files]
    Endpoints --> E3[Backup Files]
    Endpoints --> E4[250+ Common Paths]
    
    Scanner --> CVE[cveMatching.ts]
    CVE --> Detect[Version Detection]
    CVE --> Match[CVE Database Lookup]
    
    Scanner --> MITRE[mitreMapping.ts]
    MITRE --> Map[Map to ATT&CK Techniques]
    MITRE --> Severity[Calculate Severity]
    
    Active --> Score[Trust Score Calculation]
    CVE --> Score
    MITRE --> Score
    Security --> Score
    
    Score --> Results[ScanResults Component]
    Results --> Display[Display in UI]
    Results --> PDF[pdfGenerator.ts]
    
    PDF --> Report[Generate PDF Report]
    Report --> Download([User Downloads Report])
    
    style Start fill:#4ade80
    style Download fill:#4ade80
    style Scanner fill:#3b82f6
    style Active fill:#3b82f6
    style CVE fill:#8b5cf6
    style MITRE fill:#8b5cf6
    style PDF fill:#f59e0b
```

## Workflow Stages

### 1. Input Stage
- User enters one or multiple URLs via `ScannerInput` component
- URLs are parsed and validated
- Main controller (`Index.tsx`) initiates scanning process

### 2. Parallel Analysis Stage
Two main scanners run simultaneously:

#### A. Core Scanner (`scanner.ts`)
- **SEO Analysis**: Meta tags, titles, descriptions
- **Technology Detection**: Frameworks, CMS, servers, CDN
- **Network Information**: DNS, IP, geolocation
- **Security Checks**: 15+ vulnerability patterns (XSS, SQLi, open redirects, etc.)

#### B. Active Scanner (`activeScanner.ts`)
- **HTTP Header Analysis**: Checks 10 critical security headers
- **Endpoint Discovery**: Probes 250+ common paths for exposed resources

### 3. Intelligence Mapping Stage
- **CVE Matching** (`cveMatching.ts`): Detects technology versions and matches against vulnerability database
- **MITRE Mapping** (`mitreMapping.ts`): Maps findings to ATT&CK techniques and calculates severity

### 4. Scoring Stage
- Aggregates all findings
- Calculates trust score (starts at 100, deducts based on severity)
- Categorizes risk level

### 5. Output Stage
- **Display**: Results shown in UI via `ScanResults` component
- **Export**: PDF report generated on-demand with detailed findings

## Key Features

- ✅ **Client-Side Only**: No backend required, runs entirely in browser
- ✅ **Parallel Processing**: Scans multiple aspects simultaneously for speed
- ✅ **CORS Handling**: Automatic fallback to proxy when needed
- ✅ **Real-Time Progress**: Live updates during scanning
- ✅ **Comprehensive Reports**: PDF export with executive summary and compliance mapping

## Technology Stack

- **Frontend**: React, TypeScript, Tailwind CSS
- **Scanning**: Custom pattern matching and HTTP analysis
- **Intelligence**: Static CVE and MITRE ATT&CK databases
- **Reports**: jsPDF with auto-pagination

---

*Last updated: 2025-11-25*
