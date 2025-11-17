import { ScanResult, getSeverityIcon, getSeverityColor } from '@/lib/scanner';
import { Card } from './ui/card';

interface ScanResultsProps {
  results: ScanResult[];
}

export function ScanResults({ results }: ScanResultsProps) {
  if (results.length === 0) return null;

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {results.map((result, index) => (
        <Card key={index} className="p-6 space-y-6">
          <div>
            <h2 className="text-2xl font-bold mb-2">
              Results for: {result.url}
            </h2>
            <div className="space-y-2">
              <p className="text-xl">
                Overall Security Score: <span className="font-bold">{result.score} / 100</span>
              </p>
              <p className="flex items-center gap-2 text-lg">
                <span className="w-3 h-3 rounded-full bg-foreground inline-block"></span>
                {result.riskLevel}
              </p>
              {result.issues.length > 0 && (
                <div className="text-sm text-muted-foreground">
                  <p>- {result.issues.length} issue{result.issues.length !== 1 ? 's' : ''} found</p>
                  <p>
                    - {result.issues.filter(i => i.severity === 'high').length} high severity, 
                    {' '}{result.issues.filter(i => i.severity === 'medium').length} medium severity,
                    {' '}{result.issues.filter(i => i.severity === 'low').length} low severity
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Technology Detection Section */}
          <div className="space-y-4 border-t pt-4">
            <h3 className="text-xl font-bold">🔍 Technology Stack & Architecture</h3>
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
          </div>

          {result.issues.length > 0 && (
            <div className="space-y-4">
              <h3 className="text-xl font-bold">Issue List</h3>
              {result.issues.map((issue, issueIndex) => (
                <div
                  key={issueIndex}
                  className="border-l-4 pl-4 py-2 space-y-1"
                  style={{
                    borderColor: issue.severity === 'high' 
                      ? 'hsl(var(--destructive))' 
                      : issue.severity === 'medium' 
                        ? 'hsl(var(--warning))' 
                        : 'hsl(var(--info))'
                  }}
                >
                  <p className="font-semibold flex items-center gap-2">
                    <span>{getSeverityIcon(issue.severity)}</span>
                    <span className={getSeverityColor(issue.severity)}>
                      {issue.severity.charAt(0).toUpperCase() + issue.severity.slice(1)}:
                    </span>
                    {issue.title}
                  </p>
                  <p className="text-sm text-muted-foreground">{issue.description}</p>
                  <p className="text-sm">
                    <span className="font-medium">Fix:</span> {issue.fix}
                  </p>
                </div>
              ))}
            </div>
          )}

          {result.issues.length === 0 && (
            <div className="text-center py-8">
              <p className="text-xl text-success">✓ No security issues detected</p>
              <p className="text-sm text-muted-foreground mt-2">
                This website appears to have good security practices
              </p>
            </div>
          )}
        </Card>
      ))}
      
      <div className="text-center text-sm text-muted-foreground py-4">
        <p>🔒 Lightweight Scanner • No APIs • Free</p>
      </div>
    </div>
  );
}
