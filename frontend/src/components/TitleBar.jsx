import { useState, useEffect } from 'react';
import { Minus, Square, X, Copy } from 'lucide-react';

const isElectron = window.electronAPI?.isElectron;

export default function TitleBar() {
  const [max, setMax] = useState(false);

  useEffect(() => {
    if (!isElectron) return;
    const check = async () => setMax(await window.electronAPI.isMaximized());
    check();
    window.addEventListener('resize', check);
    return () => window.removeEventListener('resize', check);
  }, []);

  if (!isElectron) return null;

  return (
    <div className="h-7 bg-[var(--bg-0)] flex items-center shrink-0 border-b border-[var(--bd)]" style={{ WebkitAppRegion: 'drag' }}>
      <div className="px-3 text-[10px] font-bold tracking-[0.08em] text-[var(--t3)]" style={{ WebkitAppRegion: 'no-drag' }}>
        AI <span className="text-[var(--green)]">Security</span> Agent
      </div>
      <div className="flex-1" />
      <div className="flex h-full" style={{ WebkitAppRegion: 'no-drag' }}>
        <button onClick={() => window.electronAPI.minimize()} className="w-10 h-full flex items-center justify-center hover:bg-[var(--bg-3)] text-[var(--t3)] hover:text-[var(--t2)]">
          <Minus className="w-3 h-3" />
        </button>
        <button onClick={() => { window.electronAPI.maximize(); setMax(!max); }} className="w-10 h-full flex items-center justify-center hover:bg-[var(--bg-3)] text-[var(--t3)] hover:text-[var(--t2)]">
          {max ? <Copy className="w-2.5 h-2.5" /> : <Square className="w-2.5 h-2.5" />}
        </button>
        <button onClick={() => window.electronAPI.close()} className="w-10 h-full flex items-center justify-center hover:bg-[var(--red)] text-[var(--t3)] hover:text-white">
          <X className="w-3 h-3" />
        </button>
      </div>
    </div>
  );
}
