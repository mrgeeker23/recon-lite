ReconLite: Client-Side Security Reconnaissance Platform
Modern web security assessment typically requires backend infrastructure, paid API subscriptions, and enterprise-grade tooling inaccessible to independent researchers, small development teams, and security-conscious organizations with limited resources. ReconLite addresses this gap by providing sophisticated security reconnaissance capabilities through a pure client-side architecture—enabling automated vulnerability classification, compliance framework mapping, and threat intelligence correlation without backend dependencies or external API costs.

Technical Architecture:
Built entirely in React with TypeScript and Vite, ReconLite executes 100% in-browser as a portable static web application. The modular scanning engine performs parallel analysis across multiple security dimensions: HTTP security header validation, SSL/TLS configuration assessment, technology fingerprinting, JavaScript bundle exposure analysis, and active endpoint discovery across 250+ common administrative paths and sensitive files. The architecture leverages asynchronous JavaScript operations with intelligent request pacing to avoid WAF triggers while maintaining scan completion times under 15 seconds per target.

Intelligence Integration:
The platform implements working integrations with industry-standard security frameworks through specialized analysis modules:

MITRE ATT&CK Mapper: Correlates detected vulnerabilities to 15+ attack techniques across Initial Access, Execution, Credential Access, and Defense Evasion tactics
CVE Matching Engine: Performs semantic version comparison against known vulnerability databases, identifying outdated libraries and frameworks with disclosed CVEs including severity scores and NVD references
Compliance Framework Integration: Maps findings to PCI DSS v4.0 requirements, ISO/IEC 27001:2022 controls, NIST Cybersecurity Framework 2.0 functions, OWASP Top 10 categories, and CIS Controls v8 recommendations
Risk Classification Algorithm: Generates quantitative security scores (0-100) through multi-signal correlation, distinguishing genuine security gaps from false positives via pattern matching across headers, endpoints, and technology stacks

Regional Optimization:
ReconLite demonstrates exceptional accuracy on template-based website ecosystems prevalent across APAC markets. By recognizing recurring patterns in CMS installations (WordPress, Shopify, Drupal), shared hosting configurations, reused JavaScript libraries, and predictable endpoint structures common to government/enterprise template deployments, the scanner automatically identifies region-specific risks including outdated library versions, exposed configuration objects (.env, .git/config, backup files), missing security headers, and default administrative interfaces (/admin, /phpmyadmin, /wp-admin) that frequently appear in APAC digital infrastructure.
Key Technical Achievements:

API-Free Detection: Custom regex-based heuristics and header parsing algorithms operate without external security APIs, eliminating cost barriers and data privacy concerns
CORS Handling: Implements graceful fallback to CORS proxy (allorigins.win) when direct fetch operations are blocked, ensuring consistent scanning capability across restrictive environments
Active Reconnaissance: Parallel endpoint probing with 3-second timeouts per request tests for critical exposures (database dumps, configuration files, admin panels) while classifying findings by risk severity
Automated Reporting: PDF generation via jsPDF produces compliance-mapped security reports with executive summaries, technical findings, remediation guidance, and framework-specific recommendations

Impact & Deployment:
As a fully portable static web application requiring only npm install and npm run build for production deployment, ReconLite democratizes security assessment capabilities for security researchers, MSSPs, threat intelligence teams, penetration testers conducting pre-engagement reconnaissance, business owners performing vendor due diligence, and junior analysts lacking access to enterprise tools like Burp Suite or Nessus. Deployable via any static hosting platform (GitHub Pages, Netlify, Vercel, CloudFlare Pages), the tool serves organizations conducting rapid external posture assessments, OSINT investigations, brand monitoring, and compliance gap analysis without infrastructure constraints or recurring API costs.

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/30a9e457-f2ac-4627-b068-a82c3196ae3c) and click on Share -> Publish.

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/features/custom-domain#custom-domain)
