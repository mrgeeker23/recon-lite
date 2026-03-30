import { ScanResult, PassedCheck, getSeverityIcon, getSeverityColor } from '@/lib/scanner';
import { generatePDFReport } from '@/lib/pdfGenerator';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';
import { Progress } from './ui/progress';
import { 
  Shield, 
  Clock, 
  Activity, 
  Calendar, 
  CheckCircle2, 
  XCircle, 
  AlertCircle,
  Search,
  TrendingUp,
  ExternalLink,
  Globe,
  Server,
  Code,
  FileWarning,
  Target,
  Tag,
  Eye,
  Lock,
  Unlock,
  AlertTriangle,
  Download,
  FileText,
  Package
} from 'lucide-react';
import { NetworkSection } from './NetworkSection';
import { Button } from './ui/button';

interface ScanResultsProps {
  results: ScanResult[];
}

export function ScanResults({ results }: ScanResultsProps) {
  if (results.length === 0) return null;

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Educational Disclaimer Banner */}
      <Card className="p-4 bg-primary/5 border-primary/20">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold text-sm text-primary">Educational Demonstration Tool</p>
            <p className="text-xs text-muted-foreground">
              ReconLite is a prototype demonstrating security reconnaissance concepts. Results are based on 
              passive URL analysis and publicly available information only. This tool is for educational 
              purposes and should not replace professional security assessments. Active scans may be limited 
              by browser CORS policies.
            </p>
          </div>
        </div>
      </Card>
      
      {results.map((result, index) => (
        <div key={index} className="space-y-6">
          {/* Header Card */}
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-3xl font-bold mb-2">
                    {result.url}
                  </h2>
                  <div className="flex flex-wrap gap-4 items-center">
                    <div className="flex items-center gap-2">
                      <Shield className="w-5 h-5" />
                      <span className="text-lg">Security Score: <span className="font-bold text-2xl">{result.score}/100</span></span>
                    </div>
                    <Badge 
                      variant={result.score >= 75 ? 'default' : result.score >= 50 ? 'secondary' : 'destructive'}
                      className="text-base px-4 py-1"
                    >
                      {result.riskLevel}
                    </Badge>
                  </div>
                </div>
                <Button
                  onClick={() => generatePDFReport(result)}
                  variant="outline"
                  size="lg"
                  className="flex items-center gap-2"
                >
                  <Download className="w-5 h-5" />
                  Export PDF Report
                </Button>
              </div>
              
              {result.issues.length > 0 && (
                <div className="flex flex-wrap gap-4 text-sm">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold">Total Issues:</span>
                    <Badge variant="outline">{result.issues.length}</Badge>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">🚨</span>
                    <span>{result.issues.filter(i => i.severity === 'critical').length} Critical</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <XCircle className="w-4 h-4 text-destructive" />
                    <span>{result.issues.filter(i => i.severity === 'high').length} High</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-warning" />
                    <span>{result.issues.filter(i => i.severity === 'medium').length} Medium</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-info" />
                    <span>{result.issues.filter(i => i.severity === 'low').length} Low</span>
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Website Health Metrics */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Activity className="w-6 h-6" />
              Website Health Metrics
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground flex items-center gap-1">
                  <TrendingUp className="w-3 h-3" />
                  Uptime
                </p>
                <p className="text-xl font-bold">{result.healthMetrics.uptime}</p>
              </div>
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Response Time
                </p>
                <p className="text-xl font-bold">{result.healthMetrics.responseTime}ms</p>
              </div>
              {result.healthMetrics.certificateExpiry && (
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground flex items-center gap-1">
                    <Shield className="w-3 h-3" />
                    SSL Expires
                  </p>
                  <p className="text-sm font-semibold">{result.healthMetrics.certificateExpiry}</p>
                </div>
              )}
              {result.healthMetrics.lastModified && (
                <div className="space-y-1">
                  <p className="text-sm text-muted-foreground flex items-center gap-1">
                    <Calendar className="w-3 h-3" />
                    Last Modified
                  </p>
                  <p className="text-sm font-semibold">{result.healthMetrics.lastModified}</p>
                </div>
              )}
            </div>
          </Card>

          {/* Trust Score Circle */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Overall Trust Score
            </h3>
            <div className="flex items-center justify-center">
              <div className="relative w-48 h-48">
                <svg className="w-full h-full transform -rotate-90">
                  <circle
                    cx="96"
                    cy="96"
                    r="80"
                    stroke="currentColor"
                    strokeWidth="12"
                    fill="none"
                    className="text-muted"
                  />
                  <circle
                    cx="96"
                    cy="96"
                    r="80"
                    stroke="currentColor"
                    strokeWidth="12"
                    fill="none"
                    strokeDasharray={`${2 * Math.PI * 80}`}
                    strokeDashoffset={`${2 * Math.PI * 80 * (1 - result.trustScore / 100)}`}
                    className={
                      result.trustScore >= 70 ? 'text-success' :
                      result.trustScore >= 40 ? 'text-warning' :
                      'text-destructive'
                    }
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                  <span className="text-5xl font-bold">{result.trustScore}</span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                </div>
              </div>
            </div>
            <p className="text-center text-sm text-muted-foreground mt-4">
              {result.trustScore >= 70 ? 'Site appears trustworthy' :
               result.trustScore >= 40 ? 'Exercise caution - some risk indicators present' :
               'High risk - avoid interaction'}
            </p>
          </Card>

          {/* Suspicion Tags */}
          {result.suspicionTags.length > 0 && (
            <Card className="p-6">
              <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
                <Tag className="w-6 h-6" />
                Site Classification
              </h3>
              <div className="flex flex-wrap gap-2">
                {result.suspicionTags.map((tag, idx) => {
                  const isDangerous = tag === 'Scam Template' || tag === 'Phishing Kit';
                  const isWarning = tag === 'Outdated WordPress Theme' || tag === 'Government Clone';
                  return (
                    <Badge 
                      key={idx}
                      variant={isDangerous ? 'destructive' : isWarning ? 'secondary' : 'default'}
                      className="text-sm px-3 py-1"
                    >
                      {tag}
                    </Badge>
                  );
                })}
              </div>
            </Card>
          )}

          {/* Risk Themes */}
          {result.riskThemes.length > 0 && (
            <Card className="p-6">
              <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
                <Target className="w-6 h-6" />
                Risk Themes Analysis
              </h3>
              <div className="space-y-4">
                {result.riskThemes.map((theme, idx) => (
                  <div key={idx} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge 
                          variant={
                            theme.severity === 'critical' ? 'destructive' :
                            theme.severity === 'high' ? 'destructive' :
                            theme.severity === 'medium' ? 'secondary' : 'default'
                          }
                        >
                          {theme.severity.toUpperCase()}
                        </Badge>
                        <span className="font-semibold">{theme.theme}</span>
                      </div>
                      <span className="text-sm font-bold">{theme.score}/100</span>
                    </div>
                    <Progress value={theme.score} className="h-2" />
                    <ul className="text-sm text-muted-foreground space-y-1 ml-4">
                      {theme.findings.map((finding, fIdx) => (
                        <li key={fIdx} className="list-disc">{finding}</li>
                      ))}
                    </ul>
                    {idx < result.riskThemes.length - 1 && <Separator className="mt-4" />}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Port Scan Summary */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Server className="w-6 h-6" />
              Port Scan Summary (Passive Only)
            </h3>
            <p className="text-sm text-muted-foreground mb-4">{result.portScan.summary}</p>
            {result.portScan.exposedPorts.length > 0 && (
              <div className="space-y-3">
                {result.portScan.exposedPorts.map((port, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-lg border ${
                      port.risk === 'high' ? 'bg-destructive/10 border-destructive/30' :
                      port.risk === 'medium' ? 'bg-warning/10 border-warning/30' :
                      'bg-muted/10 border-border'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-lg">{port.port}</span>
                        <Badge variant="outline">{port.service}</Badge>
                        <Badge variant={
                          port.risk === 'high' ? 'destructive' :
                          port.risk === 'medium' ? 'secondary' : 'default'
                        }>
                          {port.risk.toUpperCase()}
                        </Badge>
                      </div>
                      {port.risk === 'high' ? <Unlock className="w-5 h-5 text-destructive" /> : <Lock className="w-5 h-5" />}
                    </div>
                    <p className="text-sm text-muted-foreground">{port.exposureHint}</p>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* Framework & Plugin Exposure Risk */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Code className="w-6 h-6" />
              Framework & Platform Risk
            </h3>
            {result.frameworkRisk.framework && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-semibold text-lg">{result.frameworkRisk.framework}</p>
                    <p className="text-sm text-muted-foreground">{result.frameworkRisk.version}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-sm text-muted-foreground">Risk Score</p>
                    <p className="text-3xl font-bold text-destructive">{result.frameworkRisk.riskScore}/100</p>
                  </div>
                </div>
                <Progress value={result.frameworkRisk.riskScore} className="h-2" />
                <Separator />
                <div>
                  <p className="font-semibold mb-2">Known Vulnerabilities:</p>
                  <ul className="space-y-1">
                    {result.frameworkRisk.vulnerabilities.map((vuln, idx) => (
                      <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0 mt-0.5" />
                        {vuln}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="p-3 bg-muted/50 rounded-lg">
                  <p className="text-sm font-semibold mb-1">Recommendation:</p>
                  <p className="text-sm text-muted-foreground">{result.frameworkRisk.recommendation}</p>
                </div>
              </div>
            )}
          </Card>

          {/* JavaScript Security Analysis */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <FileWarning className="w-6 h-6" />
              JavaScript Security Analysis
            </h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold">Risk Level:</span>
                <Badge variant={
                  result.jsSecurity.riskLevel === 'high' ? 'destructive' :
                  result.jsSecurity.riskLevel === 'medium' ? 'secondary' : 'default'
                }>
                  {result.jsSecurity.riskLevel.toUpperCase()}
                </Badge>
              </div>
              
              {result.jsSecurity.exposedSecrets.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="font-semibold mb-3">Exposed Secrets & Credentials:</p>
                    <div className="space-y-2">
                      {result.jsSecurity.exposedSecrets.map((secret, idx) => (
                        <div
                          key={idx}
                          className={`p-3 rounded-lg border ${
                            secret.severity === 'high' ? 'bg-destructive/10 border-destructive/30' :
                            secret.severity === 'medium' ? 'bg-warning/10 border-warning/30' :
                            'bg-muted/10 border-border'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold text-sm">{secret.type}</span>
                            <Badge variant={secret.severity === 'high' ? 'destructive' : 'secondary'} className="text-xs">
                              {secret.severity}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mb-1">{secret.location}</p>
                          <code className="text-xs bg-background/50 px-2 py-1 rounded">{secret.preview}</code>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
              
              {result.jsSecurity.suspiciousPatterns.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="font-semibold mb-2">Suspicious Patterns:</p>
                    <ul className="space-y-1">
                      {result.jsSecurity.suspiciousPatterns.map((pattern, idx) => (
                        <li key={idx} className="text-sm text-muted-foreground flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 text-warning" />
                          {pattern}
                        </li>
                      ))}
                    </ul>
                  </div>
                </>
              )}
            </div>
          </Card>

          {/* Scam Template Detection */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Eye className="w-6 h-6" />
              Scam Template Detection
            </h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold">Template Match:</span>
                <span className="text-2xl font-bold">{result.scamDetection.templateMatch}%</span>
              </div>
              <Progress value={result.scamDetection.templateMatch} className="h-3" />
              
              <div className="p-4 bg-muted/50 rounded-lg">
                <p className="text-sm font-semibold mb-2">Analysis Verdict:</p>
                <p className="text-sm text-muted-foreground">{result.scamDetection.overallVerdict}</p>
              </div>
              
              {result.scamDetection.matchedTemplates.length > 0 && (
                <>
                  <Separator />
                  <div>
                    <p className="font-semibold mb-2">Matched Scam Templates:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.scamDetection.matchedTemplates.map((template, idx) => (
                        <Badge key={idx} variant="destructive">{template}</Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}
              
              <Separator />
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground mb-1">JS Kit Match</p>
                  <div className="flex items-center gap-2">
                    {result.scamDetection.jsKitMatch ? (
                      <>
                        <XCircle className="w-5 h-5 text-destructive" />
                        <span className="font-semibold text-destructive">Detected</span>
                      </>
                    ) : (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-success" />
                        <span className="font-semibold text-success">Clean</span>
                      </>
                    )}
                  </div>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground mb-1">Redirect Behavior</p>
                  <Badge variant={
                    result.scamDetection.redirectBehavior === 'dangerous' ? 'destructive' :
                    result.scamDetection.redirectBehavior === 'suspicious' ? 'secondary' : 'default'
                  }>
                    {result.scamDetection.redirectBehavior.toUpperCase()}
                  </Badge>
                </div>
              </div>
            </div>
          </Card>

          {/* Passive Crawl Results */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Search className="w-6 h-6" />
              Passive Crawl Analysis
            </h3>
            <p className="text-sm text-muted-foreground mb-4">{result.passiveCrawl.summary}</p>
            {result.passiveCrawl.discoveredPaths.length > 0 && (
              <div className="space-y-2">
                {result.passiveCrawl.discoveredPaths.map((path, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center justify-between p-3 rounded-lg border ${
                      path.risk === 'high' ? 'bg-destructive/10 border-destructive/30' :
                      path.risk === 'medium' ? 'bg-warning/10 border-warning/30' :
                      'bg-muted/10 border-border'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <code className="text-sm font-mono bg-background/50 px-2 py-1 rounded">{path.path}</code>
                      <Badge variant="outline" className="text-xs">{path.type}</Badge>
                    </div>
                    <Badge variant={
                      path.risk === 'high' ? 'destructive' :
                      path.risk === 'medium' ? 'secondary' : 'default'
                    }>
                      {path.risk.toUpperCase()}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* SEO Analysis */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <Search className="w-6 h-6" />
              SEO Analysis
            </h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-semibold">SEO Score:</span>
                <span className="text-2xl font-bold">{result.seo.seoScore}/100</span>
              </div>
              <Separator />
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Title Tag</span>
                  {result.seo.hasTitle ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                {result.seo.titleLength && (
                  <div className="text-sm text-muted-foreground col-span-2">
                    Length: {result.seo.titleLength} characters {result.seo.titleLength > 60 && '(too long)'}
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-sm">Meta Description</span>
                  {result.seo.hasMetaDescription ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                {result.seo.metaDescriptionLength && (
                  <div className="text-sm text-muted-foreground col-span-2">
                    Length: {result.seo.metaDescriptionLength} characters {result.seo.metaDescriptionLength > 160 && '(too long)'}
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-sm">H1 Tag</span>
                  {result.seo.hasH1 ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Canonical URL</span>
                  {result.seo.hasCanonical ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Robots Meta</span>
                  {result.seo.hasRobotsMeta ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Sitemap</span>
                  {result.seo.hasSitemap ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Structured Data</span>
                  {result.seo.hasStructuredData ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Mobile Responsive</span>
                  {result.seo.mobileResponsive ? (
                    <CheckCircle2 className="w-4 h-4 text-success" />
                  ) : (
                    <XCircle className="w-4 h-4 text-destructive" />
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Page Load Speed</span>
                  <Badge variant={
                    result.seo.pageLoadSpeed === 'fast' ? 'default' : 
                    result.seo.pageLoadSpeed === 'moderate' ? 'secondary' : 
                    'destructive'
                  }>
                    {result.seo.pageLoadSpeed}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Image Optimization</span>
                  <Badge variant={
                    result.seo.imageOptimization === 'good' ? 'default' : 
                    result.seo.imageOptimization === 'fair' ? 'secondary' : 
                    'destructive'
                  }>
                    {result.seo.imageOptimization}
                  </Badge>
                </div>
              </div>
            </div>
          </Card>

          <NetworkSection network={result.network} />

          {/* External Reputation Checks */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
              <ExternalLink className="w-6 h-6" />
              External Reputation Checks
            </h3>
            <p className="text-sm text-muted-foreground mb-4">
              Click any button below to scan this URL on external security platforms (opens in new tab)
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => window.open(`https://www.virustotal.com/gui/url/${encodeURIComponent(result.url)}`, '_blank')}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                Scan on VirusTotal
              </Button>
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => window.open(`https://urlscan.io/search/#${result.url}`, '_blank')}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                Check on URLScan.io
              </Button>
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => window.open(`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(result.url)}`, '_blank')}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                Check on Google Safe Browsing
              </Button>
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => window.open(`https://safeweb.norton.com/report/show?url=${encodeURIComponent(result.url)}`, '_blank')}
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                Check on Norton SafeWeb
              </Button>
            </div>
          </Card>

          {/* RTI Engine (Regional Threat Intelligence) */}
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold flex items-center gap-2">
                  <Globe className="w-6 h-6" />
                  ⭐ RTI Engine (Regional Threat Intelligence Engine)
                </h3>
                <Badge 
                  variant={
                    result.rti.likelihood >= 75 ? 'destructive' : 
                    result.rti.likelihood >= 50 ? 'secondary' : 
                    'default'
                  }
                  className="text-lg px-4 py-1"
                >
                  {result.rti.likelihood}% Likelihood
                </Badge>
              </div>
              
              <p className="text-sm text-muted-foreground">
                Trained on APAC-centric and global web threat patterns.
              </p>

              <div className="p-4 bg-muted rounded-lg">
                <p className="text-sm font-medium">{result.rti.verdict}</p>
              </div>

              <Separator />

              <div>
                <h4 className="font-semibold mb-3">Regional Indicators</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {result.rti.regionalIndicators.map((indicator, idx) => (
                    <div key={idx} className="p-3 border rounded-lg">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{indicator.indicator}</span>
                        <Badge 
                          variant={
                            indicator.risk === 'high' ? 'destructive' : 
                            indicator.risk === 'medium' ? 'secondary' : 
                            'default'
                          }
                          className="text-xs"
                        >
                          {indicator.risk}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{indicator.value}</p>
                    </div>
                  ))}
                </div>
              </div>

              <Separator />

              <div>
                <h4 className="font-semibold mb-3">APAC Threat Pattern Analysis</h4>
                <p className="text-xs text-muted-foreground mb-3">
                  Checking for: Cheap shared hosting (cPanel, Plesk) • Outdated WordPress • External JS from unknown .asia/.pw domains • 
                  Redirects to scam campaigns • APAC phishing kit structures • SEA threat group JS naming • Missing TLS • Gov-like phishing clones
                </p>
                <div className="space-y-3">
                  {result.rti.detectedPatterns.map((pattern, idx) => (
                    <div 
                      key={idx} 
                      className={`p-3 border rounded-lg ${
                        pattern.detected ? 'border-destructive bg-destructive/5' : 'border-border'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {pattern.detected ? (
                          <XCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
                        ) : (
                          <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="font-medium text-sm mb-1">{pattern.category}</div>
                          <p className="text-xs text-muted-foreground">{pattern.details}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          {/* Technology Detection Section */}
          <Card className="p-6">
            <h3 className="text-2xl font-bold mb-4">🔍 Technology Stack & Architecture</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {result.technology.server && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">Server</p>
                  <p className="text-base">{result.technology.server}</p>
                </div>
              )}
              {result.technology.language && result.technology.language.length > 0 && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">Languages</p>
                  <p className="text-base">{result.technology.language.join(', ')}</p>
                </div>
              )}
              {result.technology.framework && result.technology.framework.length > 0 && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">Framework</p>
                  <p className="text-base">{result.technology.framework.join(', ')}</p>
                </div>
              )}
              {result.technology.cms && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">CMS</p>
                  <p className="text-base">{result.technology.cms}</p>
                </div>
              )}
              {result.technology.cdn && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">CDN</p>
                  <p className="text-base">{result.technology.cdn}</p>
                </div>
              )}
              {result.technology.security && result.technology.security.length > 0 && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">Security Features</p>
                  <p className="text-base">{result.technology.security.join(', ')}</p>
                </div>
              )}
              {result.technology.analytics && result.technology.analytics.length > 0 && (
                <div className="space-y-1">
                  <p className="font-semibold text-sm text-muted-foreground">Analytics</p>
                  <p className="text-base">{result.technology.analytics.join(', ')}</p>
                </div>
              )}
            </div>
          </Card>

          {/* Security Issues */}
          {result.issues.length > 0 && (
            <Card className="p-6">
              <h3 className="text-2xl font-bold mb-6">🔒 Security Issues Detected</h3>
              <div className="space-y-6">
                {result.issues.map((issue, issueIndex) => (
                  <div
                    key={issueIndex}
                    className="border-l-4 pl-6 py-4 space-y-4 bg-muted/30 rounded-r-lg"
                    style={{
                      borderColor: issue.severity === 'high' 
                        ? 'hsl(var(--destructive))' 
                        : issue.severity === 'medium' 
                          ? 'hsl(var(--warning))' 
                          : 'hsl(var(--info))'
                    }}
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-2xl">{getSeverityIcon(issue.severity)}</span>
                      <div className="flex-1 space-y-3">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={
                            issue.severity === 'high' ? 'destructive' : 
                            issue.severity === 'medium' ? 'secondary' : 
                            'outline'
                          }>
                            {issue.severity.toUpperCase()}
                          </Badge>
                          <h4 className="text-xl font-bold">{issue.title}</h4>
                        </div>
                        
                        <div className="space-y-2">
                          <p className="text-base leading-relaxed">{issue.description}</p>
                        </div>

                        <div className="space-y-2 pt-2">
                          <h5 className="font-bold text-sm uppercase text-destructive">Impact</h5>
                          <p className="text-sm leading-relaxed bg-destructive/10 p-3 rounded-md">
                            {issue.impact}
                          </p>
                        </div>

                        <div className="space-y-2">
                          <h5 className="font-bold text-sm uppercase text-muted-foreground">Technical Details</h5>
                          <p className="text-sm leading-relaxed text-muted-foreground">
                            {issue.technicalDetails}
                          </p>
                        </div>

                        <div className="space-y-2 pt-2">
                          <h5 className="font-bold text-sm uppercase text-success">Recommended Fix</h5>
                          <p className="text-sm leading-relaxed bg-success/10 p-3 rounded-md">
                            {issue.fix}
                          </p>
                        </div>

                        {issue.references && issue.references.length > 0 && (
                          <div className="space-y-2 pt-2">
                            <h5 className="font-bold text-sm uppercase text-muted-foreground">References</h5>
                            <ul className="text-sm space-y-1 text-info">
                              {issue.references.map((ref, refIndex) => (
                                <li key={refIndex}>• {ref}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {result.issues.length === 0 && (
            <Card className="p-8 text-center bg-success/10">
              <CheckCircle2 className="w-16 h-16 text-success mx-auto mb-4" />
              <p className="text-2xl font-bold text-success mb-2">✓ No security issues detected</p>
              <p className="text-muted-foreground">
                This website appears to follow security best practices
              </p>
            </Card>
          )}

          {/* Passed Security Checks */}
          {result.passedChecks && result.passedChecks.length > 0 && (
            <Card className="p-6">
              <div className="flex items-center gap-3 mb-6">
                <CheckCircle2 className="w-6 h-6 text-success" />
                <h3 className="text-2xl font-bold">✓ Passed Security Checks</h3>
              </div>
              <p className="text-muted-foreground mb-4">
                The following security controls were tested and verified to be properly implemented:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {result.passedChecks.map((check, checkIndex) => (
                  <div
                    key={checkIndex}
                    className="flex items-start gap-3 p-4 bg-success/10 border border-success/30 rounded-lg hover:bg-success/15 transition-colors"
                  >
                    <CheckCircle2 className="w-5 h-5 text-success flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="font-semibold text-sm text-foreground">{check.title}</p>
                      <p className="text-xs text-muted-foreground mt-1">{check.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      ))}
      
      <div className="text-center text-sm text-muted-foreground py-4">
        <p>🔒 Lightweight Scanner • No APIs • Free</p>
      </div>
    </div>
  );
}
