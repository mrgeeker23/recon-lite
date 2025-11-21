import { useState } from 'react';
import { ScannerInput } from '@/components/ScannerInput';
import { ScanProgress } from '@/components/ScanProgress';
import { ScanResults } from '@/components/ScanResults';
import { ThemeToggle } from '@/components/ThemeToggle';
import { parseUrls, scanUrl, ScanResult } from '@/lib/scanner';

const Index = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [currentUrl, setCurrentUrl] = useState('');
  const [progress, setProgress] = useState(0);
  const [estimatedTime, setEstimatedTime] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([]);

  const handleScan = async (inputUrls: string[]) => {
    const validUrls = parseUrls(inputUrls.join('\n'));
    
    if (validUrls.length === 0) {
      return;
    }

    setIsScanning(true);
    setResults([]);
    const newResults: ScanResult[] = [];

    for (let i = 0; i < validUrls.length; i++) {
      const url = validUrls[i];
      setCurrentUrl(url);
      setProgress(0);
      
      // Estimate time between 3-5 seconds per URL
      const scanTime = 3 + Math.random() * 2;
      setEstimatedTime(Math.round(scanTime));

      // Animate progress
      const startTime = Date.now();
      const progressInterval = setInterval(() => {
        const elapsed = (Date.now() - startTime) / 1000;
        const newProgress = Math.min((elapsed / scanTime) * 100, 99);
        setProgress(newProgress);
      }, 100);

      const result = await scanUrl(url);
      clearInterval(progressInterval);
      setProgress(100);
      
      newResults.push(result);
      setResults([...newResults]);
    }

    setIsScanning(false);
    setCurrentUrl('');
    setProgress(0);
  };

  return (
    <div className="min-h-screen bg-background py-8 px-4 sm:py-12 transition-colors duration-300">
      <div className="max-w-7xl mx-auto space-y-6 sm:space-y-8">
        <div className="fixed top-4 right-4 z-50">
          <ThemeToggle />
        </div>
        
        <header className="text-center space-y-3 py-4">
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-bold font-tech tracking-tight bg-gradient-to-r from-primary via-primary/80 to-primary bg-clip-text text-transparent">
            SITE SCANNER LITE
          </h1>
          <p className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto">
            Comprehensive Website Security, SEO & Network Intelligence Scanner
          </p>
          <div className="flex flex-wrap justify-center gap-2 text-xs sm:text-sm text-muted-foreground">
            <span className="px-3 py-1 bg-primary/10 rounded-full">Security Analysis</span>
            <span className="px-3 py-1 bg-primary/10 rounded-full">SEO Audit</span>
            <span className="px-3 py-1 bg-primary/10 rounded-full">Network Intelligence</span>
            <span className="px-3 py-1 bg-primary/10 rounded-full">Technology Detection</span>
          </div>
        </header>

        <ScannerInput onScan={handleScan} isScanning={isScanning} />

        {isScanning && (
          <ScanProgress
            currentUrl={currentUrl}
            progress={progress}
            estimatedTime={estimatedTime}
          />
        )}

        <ScanResults results={results} />

        <footer className="mt-12 pt-6 border-t border-border text-center">
          <p className="text-xs text-muted-foreground">
            © {new Date().getFullYear()} abdulabdul technologies
          </p>
        </footer>
      </div>
    </div>
  );
};

export default Index;
