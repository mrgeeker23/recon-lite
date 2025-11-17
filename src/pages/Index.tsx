import { useState } from 'react';
import { ScannerInput } from '@/components/ScannerInput';
import { ScanProgress } from '@/components/ScanProgress';
import { ScanResults } from '@/components/ScanResults';
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
    <div className="min-h-screen bg-background py-12 px-4">
      <div className="max-w-6xl mx-auto space-y-8">
        <header className="text-center space-y-2">
          <h1 className="text-5xl font-bold tracking-tight">
            WEBSITE ANALYZER
          </h1>
          <p className="text-xl text-muted-foreground">
            Simple Website Security Scanner
          </p>
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
      </div>
    </div>
  );
};

export default Index;
