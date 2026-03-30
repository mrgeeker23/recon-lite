

# Plan: Add Supply Chain Security Module to ReconLite

## What It Does
Adds a new supply chain security analysis module that detects JavaScript dependencies from scanned websites, generates an SBOM (Software Bill of Materials), and flags outdated/vulnerable packages found in the tech stack.

## How It Works
Since ReconLite scans external websites (not local projects), this module will:
- Parse the HTML of scanned sites to extract JS library references (CDN links, script tags)
- Cross-reference detected libraries against a known vulnerability database (extending the existing CVE system)
- Generate an SBOM listing all detected front-end dependencies with versions
- Flag outdated/unverified packages with risk ratings

## Files to Create/Modify

### 1. Create `src/lib/supplyChainAnalyzer.ts`
- `SupplyChainResult` interface with: detected dependencies, SBOM entries, vulnerability flags
- `detectDependenciesFromHTML(html)` — regex-based extraction of JS/CSS library references from CDN URLs (cdnjs, unpkg, jsdelivr, Google APIs), inline version comments, and meta tags
- Known vulnerability database for common front-end libraries (jQuery, Bootstrap, Angular, Lodash, Moment.js, etc.) with EOL/outdated status
- `generateSBOM()` — produces structured SBOM with package name, version, source, license (where detectable), and risk status
- `flagOutdatedPackages()` — compares detected versions against known latest stable versions

### 2. Modify `src/lib/scanner.ts`
- Add `supplyChain` field to `ScanResult` interface
- Call supply chain analysis during `scanUrl()` using the fetched HTML content
- Integrate supply chain findings into trust score calculation

### 3. Modify `src/components/ScanResults.tsx`
- Add a "Supply Chain Security" section showing:
  - SBOM table (Package, Version, Source, Status, Risk)
  - Vulnerability flags with severity badges
  - Summary stats (total deps, vulnerable count, outdated count)

### 4. Modify `src/lib/pdfGenerator.ts`
- Add Supply Chain / SBOM section to the PDF report

## Technical Notes
- Detection is passive (parsing HTML for script/link tags) — consistent with ReconLite's browser-based approach
- Extends the existing CVE matching system in `cveMatching.ts` rather than duplicating
- ~30 common libraries tracked with version/vulnerability data

