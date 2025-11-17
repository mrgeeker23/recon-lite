import { Progress } from './ui/progress';

interface ScanProgressProps {
  currentUrl: string;
  progress: number;
  estimatedTime: number;
}

export function ScanProgress({ currentUrl, progress, estimatedTime }: ScanProgressProps) {
  return (
    <div className="w-full max-w-4xl mx-auto space-y-4 p-6 bg-card border rounded-lg">
      <h3 className="text-xl font-semibold">
        Scanning: {currentUrl}
      </h3>
      <Progress value={progress} className="h-3" />
      <div className="flex justify-between text-sm text-muted-foreground">
        <span>Estimated time: {estimatedTime}s</span>
        <span className="font-semibold text-foreground">{Math.round(progress)}%</span>
      </div>
    </div>
  );
}
