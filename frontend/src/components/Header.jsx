import { Shield, Zap, Globe } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

export default function Header({ connected, healthInfo, activeFile, activePid, lang, setLang }) {
  return (
    <header className="h-14 bg-[var(--bg-1)] border-b border-[var(--bd)] flex items-center px-5 gap-4 shrink-0">
      <div className="flex items-center gap-3 min-w-0">
        <div className="w-9 h-9 rounded-lg bg-[var(--green)]/10 border border-[var(--green)]/20 flex items-center justify-center shrink-0">
          <Shield className="w-4.5 h-4.5 text-[var(--green)]" />
        </div>
        <div className="min-w-0">
          <div className="text-[15px] font-black tracking-[0.08em] text-[var(--t1)]">
            AI <span className="text-[var(--green)]">Security</span> Agent
          </div>
          <div className="text-[11px] text-[var(--t3)] tracking-[0.04em]">
            {lang === 'en' ? 'Realtime binary analysis and runtime tracing' : 'Phân tích bảo mật nhị phân và tracing runtime'}
          </div>
        </div>
      </div>

      <Separator orientation="vertical" className="h-5 bg-[var(--bd)]" />

      {activeFile && (
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2.5 bg-[var(--bg-2)] border border-[var(--bd)] rounded-lg px-3.5 py-2">
            <span className="text-[10px] text-[var(--t4)] font-semibold">FILE</span>
            <span className="text-[12px] text-[var(--blue)] font-medium truncate max-w-48">{activeFile.file_name}</span>
          </div>
          {activeFile.quick_info?.file_type && (
            <span className="text-[10px] px-2.5 py-1.5 rounded-lg bg-[var(--purple)]/10 text-[var(--purple)] border border-[var(--purple)]/20">
              {activeFile.quick_info.file_type}
            </span>
          )}
        </div>
      )}

      {activePid && (
        <div className="flex items-center gap-2.5 bg-[var(--bg-2)] border border-[var(--bd)] rounded-lg px-3.5 py-2">
          <span className="text-[10px] text-[var(--t4)] font-semibold">PID</span>
          <span className="text-[12px] text-[var(--yellow)] font-bold tabular-nums">{activePid}</span>
        </div>
      )}

      <div className="flex-1" />

      {healthInfo?.model && (
        <div className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[var(--cyan)]/5 border border-[var(--cyan)]/15">
          <Zap className="w-3 h-3 text-[var(--cyan)]" />
          <span className="text-[11px] text-[var(--cyan)] font-medium">{healthInfo.model}</span>
        </div>
      )}

      <div className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[var(--bg-2)] border border-[var(--bd)]">
        <span className="text-[10px] text-[var(--t3)] font-medium">MAVIS</span>
      </div>

      <button
        onClick={() => setLang(lang === 'vi' ? 'en' : 'vi')}
        className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[var(--bg-2)] border border-[var(--bd)] hover:border-[var(--t4)] transition-colors cursor-pointer"
      >
        <Globe className="w-3.5 h-3.5 text-[var(--t3)]" />
        <span className="text-[11px] text-[var(--t2)] font-medium">{lang === 'vi' ? 'VI' : 'EN'}</span>
      </button>

      <div className={`flex items-center gap-2 px-3.5 py-2 rounded-lg border ${
        connected
          ? 'bg-[var(--green)]/5 border-[var(--green)]/15'
          : 'bg-[var(--red)]/5 border-[var(--red)]/15'
      }`}>
        <span className={`w-2 h-2 rounded-full ${connected ? 'bg-[var(--green)] animate-[pulse-dot_2s_infinite]' : 'bg-[var(--red)]'}`} />
        <span className={`text-[11px] font-medium ${connected ? 'text-[var(--green)]' : 'text-[var(--red)]'}`}>
          {connected ? 'Online' : 'Offline'}
        </span>
      </div>
    </header>
  );
}
