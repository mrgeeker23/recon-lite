import { useState } from 'react';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';

interface ScannerInputProps {
  onScan: (urls: string[]) => void;
  isScanning: boolean;
}

export function ScannerInput({ onScan, isScanning }: ScannerInputProps) {
  const [input, setInput] = useState('');

  const handleScan = () => {
    const urls = input
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0);
    
    if (urls.length > 0) {
      onScan(urls);
    }
  };

  const handleClear = () => {
    setInput('');
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-4">
      <Textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="https://example.com&#10;https://example.com&#10;https://anotherdomain.org"
        className="min-h-[150px] text-base font-mono resize-none"
        disabled={isScanning}
      />
      <div className="flex gap-4">
        <Button
          onClick={handleScan}
          disabled={isScanning || !input.trim()}
          className="flex-1 text-base h-12"
        >
          {isScanning ? 'Scanning...' : 'Scan Now'}
        </Button>
        <Button
          onClick={handleClear}
          variant="outline"
          disabled={isScanning}
          className="flex-1 text-base h-12"
        >
          Clear
        </Button>
      </div>
    </div>
  );
}
