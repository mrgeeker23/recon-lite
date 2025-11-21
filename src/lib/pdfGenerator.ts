// PDF Report Generator for Security Scan Results
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ScanResult, SecurityIssue } from './scanner';

export function generatePDFReport(result: ScanResult): void {
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  let yPos = 20;

  // Helper function to add new page if needed
  const checkPageBreak = (requiredSpace: number) => {
    if (yPos + requiredSpace > pageHeight - 20) {
      doc.addPage();
      yPos = 20;
      return true;
    }
    return false;
  };

  // Professional Header
  doc.setFontSize(28);
  doc.setTextColor(59, 130, 246);
  doc.text('Security Assessment Report', pageWidth / 2, yPos, { align: 'center' });
  yPos += 12;
  
  doc.setFontSize(11);
  doc.setTextColor(100, 100, 100);
  doc.text('Comprehensive Security Analysis & Vulnerability Assessment', pageWidth / 2, yPos, { align: 'center' });
  yPos += 20;

  // Report Metadata Box
  doc.setDrawColor(200, 200, 200);
  doc.setLineWidth(0.5);
  doc.rect(20, yPos, pageWidth - 40, 35);
  yPos += 8;

  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  doc.setFont('helvetica', 'bold');
  doc.text('Target URL:', 25, yPos);
  doc.setFont('helvetica', 'normal');
  doc.text(result.url, 50, yPos);
  yPos += 7;

  doc.setFont('helvetica', 'bold');
  doc.text('Report Date:', 25, yPos);
  doc.setFont('helvetica', 'normal');
  doc.text(new Date().toLocaleString('en-US', { 
    year: 'numeric', month: 'long', day: 'numeric', 
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short' 
  }), 50, yPos);
  yPos += 7;

  doc.setFont('helvetica', 'bold');
  doc.text('Report ID:', 25, yPos);
  doc.setFont('helvetica', 'normal');
  doc.text(`SEC-${Date.now().toString(36).toUpperCase()}`, 50, yPos);
  yPos += 7;

  doc.setFont('helvetica', 'bold');
  doc.text('Classification:', 25, yPos);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(220, 38, 38);
  doc.text('CONFIDENTIAL - For Internal Use Only', 50, yPos);
  yPos += 15;

  // Executive Summary
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 20, yPos);
  yPos += 10;

  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  
  const summaryData = [
    ['Security Score', `${result.score}/100`],
    ['Risk Level', result.riskLevel.toUpperCase()],
    ['Trust Score', `${result.trustScore}/100`],
    ['Total Issues Identified', result.issues.length.toString()],
    ['Critical Severity Issues', result.issues.filter(i => i.severity === 'critical').length.toString()],
    ['High Severity Issues', result.issues.filter(i => i.severity === 'high').length.toString()],
    ['Medium Severity Issues', result.issues.filter(i => i.severity === 'medium').length.toString()],
    ['Low Severity Issues', result.issues.filter(i => i.severity === 'low').length.toString()]
  ];

  autoTable(doc, {
    startY: yPos,
    head: [['Assessment Metric', 'Value']],
    body: summaryData,
    theme: 'striped',
    headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold' },
    margin: { left: 20, right: 20 }
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Severity Distribution Table
  checkPageBreak(60);
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.setFont('helvetica', 'bold');
  doc.text('Severity Distribution Analysis', 20, yPos);
  yPos += 10;

  const criticalCount = result.issues.filter(i => i.severity === 'critical').length;
  const highCount = result.issues.filter(i => i.severity === 'high').length;
  const mediumCount = result.issues.filter(i => i.severity === 'medium').length;
  const lowCount = result.issues.filter(i => i.severity === 'low').length;
  const totalIssues = result.issues.length;

  const severityData = [
    [
      'Critical',
      criticalCount.toString(),
      totalIssues > 0 ? `${((criticalCount / totalIssues) * 100).toFixed(1)}%` : '0%',
      'Immediate action required',
      '< 24 hours'
    ],
    [
      'High',
      highCount.toString(),
      totalIssues > 0 ? `${((highCount / totalIssues) * 100).toFixed(1)}%` : '0%',
      'Urgent remediation needed',
      '< 7 days'
    ],
    [
      'Medium',
      mediumCount.toString(),
      totalIssues > 0 ? `${((mediumCount / totalIssues) * 100).toFixed(1)}%` : '0%',
      'Plan remediation',
      '< 30 days'
    ],
    [
      'Low',
      lowCount.toString(),
      totalIssues > 0 ? `${((lowCount / totalIssues) * 100).toFixed(1)}%` : '0%',
      'Address as resources permit',
      '< 90 days'
    ]
  ];

  autoTable(doc, {
    startY: yPos,
    head: [['Severity', 'Count', 'Percentage', 'Priority', 'Recommended SLA']],
    body: severityData,
    theme: 'striped',
    headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold' },
    margin: { left: 20, right: 20 },
    columnStyles: {
      0: { cellWidth: 25 },
      1: { cellWidth: 20, halign: 'center' },
      2: { cellWidth: 25, halign: 'center' },
      3: { cellWidth: 50 },
      4: { cellWidth: 30, halign: 'center' }
    }
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Health Metrics
  checkPageBreak(40);
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('Website Health Metrics', 20, yPos);
  yPos += 10;

  const healthData = [
    ['Uptime', result.healthMetrics.uptime],
    ['Response Time', `${result.healthMetrics.responseTime}ms`],
    ['SSL Certificate', result.healthMetrics.certificateExpiry || 'N/A'],
    ['Last Modified', result.healthMetrics.lastModified || 'N/A']
  ];

  autoTable(doc, {
    startY: yPos,
    head: [['Metric', 'Value']],
    body: healthData,
    theme: 'striped',
    headStyles: { fillColor: [59, 130, 246] },
    margin: { left: 20, right: 20 }
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Compliance Mapping Section
  doc.addPage();
  yPos = 20;
  
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.setFont('helvetica', 'bold');
  doc.text('Compliance Framework Mapping', 20, yPos);
  yPos += 10;

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(60, 60, 60);
  doc.text('Security findings mapped to industry compliance frameworks and standards.', 20, yPos);
  yPos += 12;

  // Compliance Summary Table
  const complianceData = [
    ['PCI DSS v4.0', 'Payment Card Industry Data Security Standard', getCriticalityForCompliance(criticalCount, highCount)],
    ['ISO 27001:2022', 'Information Security Management System', getCriticalityForCompliance(criticalCount, highCount)],
    ['NIST CSF 2.0', 'Cybersecurity Framework', getCriticalityForCompliance(criticalCount, highCount)],
    ['OWASP Top 10', 'Web Application Security Risks', getCriticalityForCompliance(criticalCount, highCount)],
    ['CIS Controls v8', 'Center for Internet Security', getCriticalityForCompliance(criticalCount, highCount)]
  ];

  autoTable(doc, {
    startY: yPos,
    head: [['Framework', 'Description', 'Compliance Status']],
    body: complianceData,
    theme: 'striped',
    headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold' },
    margin: { left: 20, right: 20 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { cellWidth: 80 },
      2: { cellWidth: 35, halign: 'center' }
    }
  });

  yPos = (doc as any).lastAutoTable.finalY + 15;

  // Detailed Compliance Mapping
  if (result.issues.length > 0) {
    checkPageBreak(40);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('PCI DSS v4.0 Requirements Mapping', 20, yPos);
    yPos += 8;

    const pciMappings = getPCIDSSMappings(result.issues);
    if (pciMappings.length > 0) {
      autoTable(doc, {
        startY: yPos,
        head: [['Requirement', 'Description', 'Affected Findings']],
        body: pciMappings,
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        margin: { left: 20, right: 20 },
        columnStyles: {
          0: { cellWidth: 30 },
          1: { cellWidth: 70 },
          2: { cellWidth: 50 }
        }
      });
      yPos = (doc as any).lastAutoTable.finalY + 12;
    }

    checkPageBreak(40);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('ISO 27001:2022 Controls Mapping', 20, yPos);
    yPos += 8;

    const isoMappings = getISO27001Mappings(result.issues);
    if (isoMappings.length > 0) {
      autoTable(doc, {
        startY: yPos,
        head: [['Control', 'Description', 'Affected Findings']],
        body: isoMappings,
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        margin: { left: 20, right: 20 },
        columnStyles: {
          0: { cellWidth: 30 },
          1: { cellWidth: 70 },
          2: { cellWidth: 50 }
        }
      });
      yPos = (doc as any).lastAutoTable.finalY + 12;
    }

    checkPageBreak(40);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('NIST Cybersecurity Framework Mapping', 20, yPos);
    yPos += 8;

    const nistMappings = getNISTMappings(result.issues);
    if (nistMappings.length > 0) {
      autoTable(doc, {
        startY: yPos,
        head: [['Function', 'Category', 'Affected Findings']],
        body: nistMappings,
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        margin: { left: 20, right: 20 },
        columnStyles: {
          0: { cellWidth: 30 },
          1: { cellWidth: 70 },
          2: { cellWidth: 50 }
        }
      });
      yPos = (doc as any).lastAutoTable.finalY + 15;
    }
  }

  // Security Issues with Enhanced Details
  if (result.issues.length > 0) {
    doc.addPage();
    yPos = 20;
    
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.setFont('helvetica', 'bold');
    doc.text('Detailed Security Findings', 20, yPos);
    yPos += 10;

    result.issues.forEach((issue, index) => {
      checkPageBreak(80);
      
      doc.setFontSize(12);
      doc.setTextColor(0, 0, 0);
      doc.setFont('helvetica', 'bold');
      doc.text(`Finding ${index + 1}: ${issue.title}`, 20, yPos);
      yPos += 7;

      // Severity badge
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      if (issue.severity === 'critical') {
        doc.setTextColor(153, 27, 27);
      } else if (issue.severity === 'high') {
        doc.setTextColor(220, 38, 38);
      } else if (issue.severity === 'medium') {
        doc.setTextColor(234, 179, 8);
      } else {
        doc.setTextColor(59, 130, 246);
      }
      doc.text(`SEVERITY: ${issue.severity.toUpperCase()}`, 25, yPos);
      yPos += 8;

      // Description
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(0, 0, 0);
      doc.text('Description:', 25, yPos);
      yPos += 5;
      
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(60, 60, 60);
      const descLines = doc.splitTextToSize(issue.description, pageWidth - 50);
      doc.text(descLines, 25, yPos);
      yPos += descLines.length * 5 + 5;

      // Impact
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(0, 0, 0);
      doc.text('Business Impact:', 25, yPos);
      yPos += 5;
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      const impactLines = doc.splitTextToSize(issue.impact, pageWidth - 50);
      doc.text(impactLines, 25, yPos);
      yPos += impactLines.length * 4 + 5;

      // Technical Details
      if (issue.technicalDetails) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text('Technical Details:', 25, yPos);
        yPos += 5;
        
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.setTextColor(60, 60, 60);
        const techLines = doc.splitTextToSize(issue.technicalDetails, pageWidth - 50);
        doc.text(techLines, 25, yPos);
        yPos += techLines.length * 4 + 5;
      }

      // Remediation
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(10);
      doc.setTextColor(0, 0, 0);
      doc.text('Remediation Recommendations:', 25, yPos);
      yPos += 5;
      
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.setTextColor(60, 60, 60);
      const fixLines = doc.splitTextToSize(issue.fix, pageWidth - 50);
      doc.text(fixLines, 25, yPos);
      yPos += fixLines.length * 4 + 5;

      // References
      if (issue.references && issue.references.length > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9);
        doc.setTextColor(0, 0, 0);
        doc.text('References:', 25, yPos);
        yPos += 4;
        
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(59, 130, 246);
        issue.references.forEach(ref => {
          doc.text(`• ${ref}`, 27, yPos);
          yPos += 4;
        });
        yPos += 3;
      }

      yPos += 5;
    });
  }

  // MITRE ATT&CK Mapping (if available)
  if (result.issues.some(i => i.mitreTechnique)) {
    doc.addPage();
    yPos = 20;
    
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.setFont('helvetica', 'bold');
    doc.text('MITRE ATT&CK Framework Mapping', 20, yPos);
    yPos += 10;

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    doc.text('Security findings mapped to MITRE ATT&CK techniques for comprehensive threat intelligence analysis.', 20, yPos);
    yPos += 12;

    const mitreData = result.issues
      .filter(i => i.mitreTechnique)
      .map(issue => [
        issue.mitreTechnique!.id,
        issue.mitreTechnique!.name,
        issue.mitreTechnique!.tactic,
        issue.title.substring(0, 40) + (issue.title.length > 40 ? '...' : '')
      ]);

    if (mitreData.length > 0) {
      autoTable(doc, {
        startY: yPos,
        head: [['Technique ID', 'Technique Name', 'Tactic', 'Related Finding']],
        body: mitreData,
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        margin: { left: 20, right: 20 },
        columnStyles: {
          0: { cellWidth: 25 },
          1: { cellWidth: 50 },
          2: { cellWidth: 35 },
          3: { cellWidth: 40 }
        }
      });
      yPos = (doc as any).lastAutoTable.finalY + 10;
    }
  }

  // CVE Analysis with Version Details
  if (result.network.cveAnalysis && result.network.cveAnalysis.cves.length > 0) {
    checkPageBreak(50);
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.setFont('helvetica', 'bold');
    doc.text('Known Vulnerabilities (CVE) Analysis', 20, yPos);
    yPos += 10;

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(60, 60, 60);
    doc.text('Outdated software versions detected with known Common Vulnerabilities and Exposures (CVEs).', 20, yPos);
    yPos += 12;

    const cveData = result.network.cveAnalysis.cves.map(cve => [
      cve.cveId,
      `${cve.technology} ${cve.version}`,
      cve.severity.toUpperCase(),
      cve.cvssScore.toString(),
      cve.description.substring(0, 60) + '...'
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [['CVE ID', 'Vulnerable Version', 'Severity', 'CVSS', 'Description']],
      body: cveData,
      theme: 'striped',
      headStyles: { fillColor: [59, 130, 246], fontStyle: 'bold', fontSize: 9 },
      bodyStyles: { fontSize: 8 },
      margin: { left: 20, right: 20 },
      columnStyles: {
        0: { cellWidth: 30 },
        1: { cellWidth: 35 },
        2: { cellWidth: 20, halign: 'center' },
        3: { cellWidth: 15, halign: 'center' },
        4: { cellWidth: 50 }
      }
    });

    yPos = (doc as any).lastAutoTable.finalY + 8;

    // Remediation recommendations for CVEs
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(0, 0, 0);
    doc.text('Version Upgrade Recommendations:', 20, yPos);
    yPos += 7;

    result.network.cveAnalysis.versions.forEach(version => {
      const relatedCVEs = result.network.cveAnalysis!.cves.filter(
        cve => cve.technology === version.name && cve.version === version.version
      );

      if (relatedCVEs.length > 0) {
        checkPageBreak(15);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(60, 60, 60);
        doc.text(`• ${version.name} v${version.version}`, 25, yPos);
        yPos += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(8);
        doc.text(`  Detected in HTTP headers or page content`, 25, yPos);
        yPos += 4;
        doc.text(`  Vulnerabilities: ${relatedCVEs.length} CVE(s) affecting this version`, 25, yPos);
        yPos += 4;
        doc.text(`  Recommendation: Upgrade to latest stable version immediately`, 25, yPos);
        yPos += 6;
      }
    });

    yPos += 5;
  }

  // Technology Stack
  doc.addPage();
  yPos = 20;
  
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.setFont('helvetica', 'bold');
  doc.text('Technology Stack Analysis', 20, yPos);
  yPos += 10;

  const techData: string[][] = [];
  if (result.technology.server) techData.push(['Server', result.technology.server]);
  if (result.technology.language) techData.push(['Language', result.technology.language.join(', ')]);
  if (result.technology.framework) techData.push(['Framework', result.technology.framework.join(', ')]);
  if (result.technology.cms) techData.push(['CMS', result.technology.cms]);
  if (result.technology.cdn) techData.push(['CDN', result.technology.cdn]);

  if (techData.length > 0) {
    autoTable(doc, {
      startY: yPos,
      head: [['Technology', 'Details']],
      body: techData,
      theme: 'striped',
      headStyles: { fillColor: [59, 130, 246] },
      margin: { left: 20, right: 20 }
    });
    yPos = (doc as any).lastAutoTable.finalY + 15;
  }

  // Security Headers
  if (result.network.headers && result.network.headers.securityHeaders.length > 0) {
    checkPageBreak(40);
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.setFont('helvetica', 'bold');
    doc.text('Security Headers Analysis', 20, yPos);
    yPos += 10;

    const headerData = result.network.headers.securityHeaders.map(h => [
      h.name,
      h.present ? '✓ Present' : '✗ Missing',
      h.risk.toUpperCase()
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [['Header', 'Status', 'Risk']],
      body: headerData,
      theme: 'striped',
      headStyles: { fillColor: [59, 130, 246] },
      margin: { left: 20, right: 20 }
    });
    yPos = (doc as any).lastAutoTable.finalY + 15;
  }

  // Discovered Endpoints
  if (result.network.endpoints && result.network.endpoints.endpoints.length > 0) {
    doc.addPage();
    yPos = 20;
    
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.setFont('helvetica', 'bold');
    doc.text('Discovered Endpoints & Attack Surface', 20, yPos);
    yPos += 10;

    const endpointData = result.network.endpoints.endpoints.map(e => [
      e.path,
      e.status.toString(),
      `${e.responseTime}ms`,
      e.risk.toUpperCase()
    ]);

    autoTable(doc, {
      startY: yPos,
      head: [['Path', 'Status', 'Response Time', 'Risk']],
      body: endpointData,
      theme: 'striped',
      headStyles: { fillColor: [59, 130, 246] },
      margin: { left: 20, right: 20 },
      columnStyles: {
        0: { cellWidth: 60 }
      }
    });
  }

  // Footer on last page
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} of ${totalPages}`,
      pageWidth / 2,
      pageHeight - 10,
      { align: 'center' }
    );
    doc.text(
      'Generated by Site Search Lite',
      pageWidth - 20,
      pageHeight - 10,
      { align: 'right' }
    );
  }

  // Save the PDF
  const fileName = `security-assessment-${result.url.replace(/[^a-z0-9]/gi, '_')}-${Date.now()}.pdf`;
  doc.save(fileName);
}

// Helper function to determine compliance status
function getCriticalityForCompliance(critical: number, high: number): string {
  if (critical > 0) return 'Non-Compliant';
  if (high > 2) return 'At Risk';
  if (high > 0) return 'Needs Review';
  return 'Compliant';
}

// PCI DSS Requirement Mappings
function getPCIDSSMappings(issues: SecurityIssue[]): string[][] {
  const mappings: { [key: string]: { req: string; desc: string; issues: string[] } } = {
    'req-6.2': { req: '6.2.4', desc: 'Secure coding practices', issues: [] },
    'req-6.5': { req: '6.5.1-10', desc: 'Common coding vulnerabilities', issues: [] },
    'req-4.1': { req: '4.1', desc: 'Encryption of cardholder data', issues: [] },
    'req-8.2': { req: '8.2', desc: 'Strong authentication', issues: [] },
    'req-11.3': { req: '11.3', desc: 'Penetration testing', issues: [] }
  };

  issues.forEach(issue => {
    if (issue.title.toLowerCase().includes('xss') || issue.title.toLowerCase().includes('injection')) {
      mappings['req-6.5'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('ssl') || issue.title.toLowerCase().includes('tls') || 
        issue.title.toLowerCase().includes('encryption')) {
      mappings['req-4.1'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('auth') || issue.title.toLowerCase().includes('password')) {
      mappings['req-8.2'].issues.push(issue.title);
    }
    if (issue.severity === 'critical' || issue.severity === 'high') {
      mappings['req-11.3'].issues.push(issue.title);
    }
  });

  return Object.values(mappings)
    .filter(m => m.issues.length > 0)
    .map(m => [m.req, m.desc, `${m.issues.length} finding(s)`]);
}

// ISO 27001 Control Mappings
function getISO27001Mappings(issues: SecurityIssue[]): string[][] {
  const mappings: { [key: string]: { control: string; desc: string; issues: string[] } } = {
    'a-8-8': { control: 'A.8.8', desc: 'Management of technical vulnerabilities', issues: [] },
    'a-8-16': { control: 'A.8.16', desc: 'Monitoring activities', issues: [] },
    'a-8-23': { control: 'A.8.23', desc: 'Web filtering', issues: [] },
    'a-8-24': { control: 'A.8.24', desc: 'Use of cryptography', issues: [] },
    'a-5-15': { control: 'A.5.15', desc: 'Access control', issues: [] }
  };

  issues.forEach(issue => {
    if (issue.title.toLowerCase().includes('vulnerability') || issue.title.toLowerCase().includes('cve')) {
      mappings['a-8-8'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('monitor') || issue.title.toLowerCase().includes('log')) {
      mappings['a-8-16'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('encryption') || issue.title.toLowerCase().includes('crypto')) {
      mappings['a-8-24'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('access') || issue.title.toLowerCase().includes('auth')) {
      mappings['a-5-15'].issues.push(issue.title);
    }
  });

  return Object.values(mappings)
    .filter(m => m.issues.length > 0)
    .map(m => [m.control, m.desc, `${m.issues.length} finding(s)`]);
}

// NIST CSF Mappings
function getNISTMappings(issues: SecurityIssue[]): string[][] {
  const mappings: { [key: string]: { func: string; category: string; issues: string[] } } = {
    'id-ra': { func: 'Identify', category: 'Risk Assessment (ID.RA)', issues: [] },
    'pr-ds': { func: 'Protect', category: 'Data Security (PR.DS)', issues: [] },
    'pr-ac': { func: 'Protect', category: 'Access Control (PR.AC)', issues: [] },
    'de-cm': { func: 'Detect', category: 'Security Monitoring (DE.CM)', issues: [] },
    'rs-an': { func: 'Respond', category: 'Analysis (RS.AN)', issues: [] }
  };

  issues.forEach(issue => {
    if (issue.severity === 'critical' || issue.severity === 'high') {
      mappings['id-ra'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('encryption') || issue.title.toLowerCase().includes('data')) {
      mappings['pr-ds'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('access') || issue.title.toLowerCase().includes('auth')) {
      mappings['pr-ac'].issues.push(issue.title);
    }
    if (issue.title.toLowerCase().includes('monitor') || issue.title.toLowerCase().includes('detect')) {
      mappings['de-cm'].issues.push(issue.title);
    }
  });

  return Object.values(mappings)
    .filter(m => m.issues.length > 0)
    .map(m => [m.func, m.category, `${m.issues.length} finding(s)`]);
}
