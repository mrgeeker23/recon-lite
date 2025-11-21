// PDF Report Generator for Security Scan Results
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { ScanResult } from './scanner';

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

  // Title
  doc.setFontSize(24);
  doc.setTextColor(59, 130, 246); // Primary color
  doc.text('Security Scan Report', pageWidth / 2, yPos, { align: 'center' });
  yPos += 15;

  // URL and Date
  doc.setFontSize(12);
  doc.setTextColor(100, 100, 100);
  doc.text(`URL: ${result.url}`, 20, yPos);
  yPos += 7;
  doc.text(`Generated: ${new Date().toLocaleString()}`, 20, yPos);
  yPos += 15;

  // Executive Summary
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('Executive Summary', 20, yPos);
  yPos += 10;

  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  
  const summaryData = [
    ['Security Score', `${result.score}/100`],
    ['Risk Level', result.riskLevel],
    ['Trust Score', `${result.trustScore}/100`],
    ['Total Issues', result.issues.length.toString()],
    ['High Severity', result.issues.filter(i => i.severity === 'high').length.toString()],
    ['Medium Severity', result.issues.filter(i => i.severity === 'medium').length.toString()],
    ['Low Severity', result.issues.filter(i => i.severity === 'low').length.toString()]
  ];

  autoTable(doc, {
    startY: yPos,
    head: [['Metric', 'Value']],
    body: summaryData,
    theme: 'striped',
    headStyles: { fillColor: [59, 130, 246] },
    margin: { left: 20, right: 20 }
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

  // Security Issues
  if (result.issues.length > 0) {
    checkPageBreak(40);
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('Security Issues', 20, yPos);
    yPos += 10;

    result.issues.forEach((issue, index) => {
      checkPageBreak(60);
      
      doc.setFontSize(12);
      doc.setTextColor(0, 0, 0);
      doc.text(`${index + 1}. ${issue.title}`, 20, yPos);
      yPos += 7;

      // Severity badge
      doc.setFontSize(10);
      if (issue.severity === 'high') {
        doc.setTextColor(220, 38, 38);
      } else if (issue.severity === 'medium') {
        doc.setTextColor(234, 179, 8);
      } else {
        doc.setTextColor(59, 130, 246);
      }
      doc.text(`Severity: ${issue.severity.toUpperCase()}`, 25, yPos);
      yPos += 7;

      // Description
      doc.setTextColor(60, 60, 60);
      const descLines = doc.splitTextToSize(issue.description, pageWidth - 50);
      doc.text(descLines, 25, yPos);
      yPos += descLines.length * 5 + 5;

      // Impact
      doc.setFontSize(9);
      doc.setTextColor(100, 100, 100);
      const impactLines = doc.splitTextToSize(`Impact: ${issue.impact}`, pageWidth - 50);
      doc.text(impactLines, 25, yPos);
      yPos += impactLines.length * 4 + 3;

      // Fix
      const fixLines = doc.splitTextToSize(`Fix: ${issue.fix}`, pageWidth - 50);
      doc.text(fixLines, 25, yPos);
      yPos += fixLines.length * 4 + 10;
    });
  }

  // MITRE ATT&CK Mapping (if available)
  if (result.issues.length > 0) {
    doc.addPage();
    yPos = 20;
    
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text('MITRE ATT&CK Framework Mapping', 20, yPos);
    yPos += 10;

    doc.setFontSize(9);
    doc.setTextColor(60, 60, 60);
    doc.text('Security issues mapped to MITRE ATT&CK techniques for threat intelligence.', 20, yPos);
    yPos += 10;
  }

  // Technology Stack
  doc.addPage();
  yPos = 20;
  
  doc.setFontSize(16);
  doc.setTextColor(0, 0, 0);
  doc.text('Technology Stack', 20, yPos);
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
    doc.text('Discovered Endpoints', 20, yPos);
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
  const fileName = `security-scan-${result.url.replace(/[^a-z0-9]/gi, '_')}-${Date.now()}.pdf`;
  doc.save(fileName);
}
