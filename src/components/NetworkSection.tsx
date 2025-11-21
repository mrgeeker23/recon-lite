import { NetworkInfo } from '@/lib/scanner';
import { Card } from './ui/card';
import { Badge } from './ui/badge';
import { Separator } from './ui/separator';
import { Network, Server, Globe, Radio, Link2, MapPin, Shield, ExternalLink, AlertCircle, CheckCircle, XCircle, Bug, FileText, AlertTriangle } from 'lucide-react';

interface NetworkSectionProps {
  network: NetworkInfo;
}

export function NetworkSection({ network }: NetworkSectionProps) {
  return (
    <Card className="p-6">
      <h3 className="text-2xl font-bold mb-4 flex items-center gap-2">
        <Network className="w-6 h-6" />
        Network & Infrastructure Intelligence
      </h3>
      <div className="space-y-6">
        {/* IP & DNS Information */}
        <div className="space-y-3">
          <h4 className="text-lg font-semibold flex items-center gap-2">
            <Globe className="w-5 h-5" />
            IP & DNS Information
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pl-7">
            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">IPv4 Address</p>
              <p className="font-mono text-sm">{network.ipAddress}</p>
            </div>
            {network.ipv6Address && (
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">IPv6 Address</p>
                <p className="font-mono text-sm break-all">{network.ipv6Address}</p>
              </div>
            )}
            {network.dnsRecords.map((record, idx) => (
              <div key={idx} className="space-y-1">
                <p className="text-sm text-muted-foreground">{record.type} Record</p>
                <p className="font-mono text-sm break-all">{record.value}</p>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Hosting Provider */}
        <div className="space-y-3">
          <h4 className="text-lg font-semibold flex items-center gap-2">
            <Server className="w-5 h-5" />
            Hosting Provider
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pl-7">
            {network.hosting.provider && (
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">Provider</p>
                <p className="text-sm">{network.hosting.provider}</p>
              </div>
            )}
            {network.hosting.location && (
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground flex items-center gap-1">
                  <MapPin className="w-3 h-3" />
                  Location
                </p>
                <p className="text-sm">{network.hosting.location}</p>
              </div>
            )}
            {network.hosting.asn && (
              <div className="space-y-1">
                <p className="text-sm text-muted-foreground">ASN</p>
                <p className="font-mono text-sm">{network.hosting.asn}</p>
              </div>
            )}
          </div>
        </div>

        <Separator />

        {/* Open Ports */}
        <div className="space-y-3">
          <h4 className="text-lg font-semibold flex items-center gap-2">
            <Radio className="w-5 h-5" />
            Open Ports Detected ({network.openPorts.length})
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pl-7">
            {network.openPorts.map((port, idx) => (
              <div key={idx} className="p-3 bg-muted/50 rounded-lg space-y-1">
                <div className="flex items-center justify-between">
                  <p className="font-mono text-sm font-bold">Port {port.port}</p>
                  <Badge variant={port.status === 'open' ? 'default' : 'outline'} className="text-xs">
                    {port.status}
                  </Badge>
                </div>
                <p className="text-xs text-muted-foreground">{port.service}</p>
                <p className="text-xs text-muted-foreground">{port.protocol}</p>
              </div>
            ))}
          </div>
        </div>

        <Separator />

        {/* Website Connections */}
        <div className="space-y-3">
          <h4 className="text-lg font-semibold flex items-center gap-2">
            <Link2 className="w-5 h-5" />
            Website Connections
          </h4>
          <div className="grid grid-cols-3 gap-4 pl-7">
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <p className="text-2xl font-bold">{network.connections.internal}</p>
              <p className="text-xs text-muted-foreground mt-1">Internal Links</p>
            </div>
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <p className="text-2xl font-bold">{network.connections.external}</p>
              <p className="text-xs text-muted-foreground mt-1">External Links</p>
            </div>
            <div className="text-center p-4 bg-muted/50 rounded-lg">
              <p className="text-2xl font-bold">{network.connections.thirdParty.length}</p>
              <p className="text-xs text-muted-foreground mt-1">3rd Party Services</p>
            </div>
          </div>
          {network.connections.thirdParty.length > 0 && (
            <div className="pl-7 pt-2">
              <p className="text-sm font-semibold mb-2">Third-Party Domains:</p>
              <div className="flex flex-wrap gap-2">
                {network.connections.thirdParty.map((domain, idx) => (
                  <Badge key={idx} variant="outline" className="font-mono text-xs">
                    {domain}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
        
        {/* Active Scan - Security Headers */}
        {network.activeScanPerformed && network.headers && (
          <>
            <Separator />
            <div className="space-y-3">
              <h4 className="text-lg font-semibold flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Security Headers Analysis
                <Badge variant={network.headers.score >= 75 ? 'default' : network.headers.score >= 50 ? 'outline' : 'destructive'}>
                  Score: {network.headers.score}/100
                </Badge>
              </h4>
              <div className="space-y-2 pl-7">
                {network.headers.securityHeaders.map((header, idx) => (
                  <div key={idx} className={`p-3 rounded-lg border ${
                    header.present ? 'bg-success/10 border-success/20' : 
                    header.risk === 'high' ? 'bg-destructive/10 border-destructive/20' :
                    header.risk === 'medium' ? 'bg-warning/10 border-warning/20' : 'bg-muted/50'
                  }`}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2">
                          {header.present ? <CheckCircle className="w-4 h-4 text-success" /> : <XCircle className="w-4 h-4 text-destructive" />}
                          <p className="font-mono text-sm font-semibold">{header.name}</p>
                        </div>
                        {header.value && <p className="text-xs text-muted-foreground font-mono pl-6">{header.value}</p>}
                        {header.recommendation && !header.present && <p className="text-xs text-muted-foreground pl-6">{header.recommendation}</p>}
                      </div>
                      <Badge variant={header.present ? 'default' : 'outline'} className="text-xs">{header.present ? 'Present' : 'Missing'}</Badge>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
        
        {/* Active Scan - Endpoints */}
        {network.activeScanPerformed && network.endpoints && network.endpoints.endpoints.length > 0 && (
          <>
            <Separator />
            <div className="space-y-3">
              <h4 className="text-lg font-semibold flex items-center gap-2">
                <ExternalLink className="w-5 h-5" />
                Discovered Endpoints
              </h4>
              <p className="text-sm text-muted-foreground pl-7">{network.endpoints.summary}</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pl-7">
                {network.endpoints.endpoints.map((endpoint, idx) => (
                  <div key={idx} className={`p-3 rounded-lg border ${
                    endpoint.risk === 'high' ? 'bg-destructive/10 border-destructive/20' : 
                    endpoint.risk === 'medium' ? 'bg-warning/10 border-warning/20' : 'bg-muted/50'
                  }`}>
                    <div className="flex items-center justify-between mb-1">
                      <p className="font-mono text-sm font-semibold">{endpoint.path}</p>
                      <Badge variant="outline" className="text-xs">{endpoint.status}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{endpoint.details}</p>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
        
        {/* CVE Analysis */}
        {network.cveAnalysis && (network.cveAnalysis.versions.length > 0 || network.cveAnalysis.cves.length > 0) && (
          <>
            <Separator />
            <div className="space-y-3">
              <h4 className="text-lg font-semibold flex items-center gap-2">
                <Bug className="w-5 h-5" />
                CVE Version Matching
              </h4>
              
              {network.cveAnalysis.versions.length > 0 && (
                <div className="pl-7 space-y-2">
                  <p className="text-sm font-semibold">Detected Versions:</p>
                  {network.cveAnalysis.versions.map((v, idx) => (
                    <div key={idx} className="p-2 bg-muted/50 rounded text-xs">
                      <span className="font-semibold">{v.name} {v.version}</span> - {v.detectedFrom}
                    </div>
                  ))}
                </div>
              )}
              
              {network.cveAnalysis.cves.length > 0 && (
                <div className="pl-7 space-y-2">
                  <p className="text-sm font-semibold text-destructive flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    Known CVEs: {network.cveAnalysis.cves.length}
                  </p>
                  {network.cveAnalysis.cves.map((cve, idx) => (
                    <div key={idx} className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg">
                      <div className="flex items-center gap-2 mb-1">
                        <a href={cve.url} target="_blank" rel="noopener noreferrer" className="font-bold text-sm hover:underline">
                          {cve.cveId}
                        </a>
                        <Badge variant="destructive" className="text-xs">{cve.severity}</Badge>
                      </div>
                      <p className="text-xs mb-1">{cve.description}</p>
                      <p className="text-xs text-muted-foreground">CVSS: {cve.cvssScore}/10 | {cve.publishedDate}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </Card>
  );
}