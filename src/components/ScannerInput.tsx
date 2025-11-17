import { useState, useRef } from 'react';
import { Button } from './ui/button';
import { Textarea } from './ui/textarea';
import { useToast } from '@/hooks/use-toast';

interface ScannerInputProps {
  onScan: (urls: string[]) => void;
  isScanning: boolean;
}

export function ScannerInput({ onScan, isScanning }: ScannerInputProps) {
  const [input, setInput] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

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

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const fileType = file.name.split('.').pop()?.toLowerCase();
    if (fileType !== 'txt' && fileType !== 'csv') {
      toast({
        title: 'Invalid file type',
        description: 'Please upload a .txt or .csv file',
        variant: 'destructive',
      });
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      const urls = content
        .split(/[\n,]/)
        .map(line => line.trim())
        .filter(line => line.length > 0);
      
      setInput(urls.join('\n'));
      toast({
        title: 'File loaded',
        description: `Loaded ${urls.length} URLs from file`,
      });
    };
    reader.readAsText(file);
    
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
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
          onClick={() => fileInputRef.current?.click()}
          variant="secondary"
          disabled={isScanning}
          className="flex-1 text-base h-12"
        >
          Upload File (TXT/CSV)
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
      <input
        ref={fileInputRef}
        type="file"
        accept=".txt,.csv"
        onChange={handleFileUpload}
        className="hidden"
      />
    </div>
  );
}
