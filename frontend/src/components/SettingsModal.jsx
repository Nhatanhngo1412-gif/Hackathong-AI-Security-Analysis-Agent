import { useState, useEffect } from 'react';
import { Key, Globe, Cpu, Palette } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

export default function SettingsModal({ open, onOpenChange, healthInfo }) {
  const [apiKey, setApiKey] = useState('');
  const [model, setModel] = useState(healthInfo?.model || 'gpt-4o');
  const [baseUrl, setBaseUrl] = useState('');
  const [saved, setSaved] = useState(false);
  const [theme, setTheme] = useState('dark-default');
  const [fontSize, setFontSize] = useState('medium');
  const [language, setLanguage] = useState('vi');

  useEffect(() => {
    fetch('/api/settings').then((r) => r.json()).then((d) => {
      setApiKey(d.api_key_masked || '');
      setModel(d.model || 'gpt-4o');
      setBaseUrl(d.base_url || '');
    });
  }, []);

  const save = async () => {
    const body = { model, base_url: baseUrl };
    if (apiKey && !apiKey.includes('...')) body.api_key = apiKey;
    await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    setSaved(true);
    setTimeout(() => { setSaved(false); onOpenChange(false); }, 800);
  };

  const presets = [
    { label: 'OpenAI', url: '', models: ['gpt-4o', 'gpt-4o-mini', 'o1', 'o3-mini'] },
    { label: 'OpenRouter', url: 'https://openrouter.ai/api/v1', models: ['openai/gpt-4o', 'anthropic/claude-3.5-sonnet', 'google/gemini-2.0-flash-exp'] },
  ];

  const themes = [
    { id: 'dark-default', name: 'Tối (mặc định)', bg: '#08090d', accent: '#22c55e' },
    { id: 'midnight', name: 'Midnight Blue', bg: '#0a0f1e', accent: '#3b82f6' },
    { id: 'hacker', name: 'Hacker', bg: '#000000', accent: '#00ff00' },
  ];

  const fontSizes = [
    { id: 'small', label: 'Nhỏ' },
    { id: 'medium', label: 'Vừa' },
    { id: 'large', label: 'Lớn' },
  ];

  const languages = [
    { id: 'vi', label: 'Tiếng Việt' },
    { id: 'en', label: 'English' },
    { id: 'auto', label: 'Tự động' },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[720px] bg-[var(--bg-2)] border-[var(--bd)] text-[var(--t1)]" showCloseButton={false}>
        <DialogHeader className="px-7 pt-6 pb-2">
          <DialogTitle className="text-[16px] font-bold tracking-wide">Cài đặt</DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="provider" className="w-full">
          <TabsList className="w-full justify-start rounded-none border-b border-[var(--bd)] bg-transparent h-auto px-7 gap-2">
            <TabsTrigger
              value="provider"
              className="rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-transparent data-[state=active]:shadow-none bg-transparent text-[var(--t3)] px-4 py-3 text-[13px] font-medium gap-2"
            >
              <Cpu className="w-4 h-4" /> AI Provider
            </TabsTrigger>
            <TabsTrigger
              value="appearance"
              className="rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-transparent data-[state=active]:shadow-none bg-transparent text-[var(--t3)] px-4 py-3 text-[13px] font-medium gap-2"
            >
              <Palette className="w-4 h-4" /> Giao diện
            </TabsTrigger>
          </TabsList>

          <TabsContent value="provider" className="px-7 py-6 mt-0">
            <div className="space-y-7">
              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase">Provider</Label>
                <div className="flex gap-3">
                  {presets.map((p) => (
                    <button
                      key={p.label}
                      onClick={() => { setBaseUrl(p.url); setModel(p.models[0]); }}
                      className={`px-5 py-2.5 rounded-md text-[13px] font-medium transition-all ${
                        baseUrl === p.url
                          ? 'bg-[var(--green)]/15 text-[var(--green)] ring-1 ring-[var(--green)]/25'
                          : 'bg-[var(--bg-3)] text-[var(--t3)] hover:text-[var(--t2)] hover:bg-[var(--bg-4)]'
                      }`}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase flex items-center gap-2">
                  <Key className="w-3.5 h-3.5" /> API Key
                </Label>
                <Input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder="sk-..."
                  className="bg-[var(--bg-0)] border-[var(--bd)] text-[var(--t1)] placeholder:text-[var(--t4)] h-12 text-[14px] px-4 rounded-md focus-visible:ring-[var(--green)]/30 focus-visible:border-[var(--green)]/30"
                />
              </div>

              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5" /> Model
                </Label>
                <Input
                  type="text"
                  value={model}
                  onChange={(e) => setModel(e.target.value)}
                  className="bg-[var(--bg-0)] border-[var(--bd)] text-[var(--t1)] h-12 text-[14px] px-4 rounded-md focus-visible:ring-[var(--green)]/30 focus-visible:border-[var(--green)]/30"
                />
                <div className="flex gap-2.5 flex-wrap pt-1">
                  {(presets.find((p) => p.url === baseUrl)?.models || []).map((m) => (
                    <button
                      key={m}
                      onClick={() => setModel(m)}
                      className={`px-4 py-2 rounded-md text-[12px] font-medium transition-all ${
                        model === m
                          ? 'bg-[var(--cyan)]/15 text-[var(--cyan)] ring-1 ring-[var(--cyan)]/25'
                          : 'bg-[var(--bg-3)] text-[var(--t2)] hover:text-[var(--t1)] hover:bg-[var(--bg-4)]'
                      }`}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase flex items-center gap-2">
                  <Globe className="w-3.5 h-3.5" /> Base URL
                  <span className="font-normal normal-case tracking-normal text-[var(--t4)]">(trống = mặc định)</span>
                </Label>
                <Input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="https://api.openai.com/v1"
                  className="bg-[var(--bg-0)] border-[var(--bd)] text-[var(--t1)] placeholder:text-[var(--t4)] h-12 text-[14px] px-4 rounded-md focus-visible:ring-[var(--green)]/30 focus-visible:border-[var(--green)]/30"
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="appearance" className="px-7 py-6 mt-0">
            <div className="space-y-7">
              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase">Theme</Label>
                <div className="grid grid-cols-3 gap-3">
                  {themes.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setTheme(t.id)}
                      className={`p-4 rounded-md text-left transition-all ${
                        theme === t.id
                          ? 'bg-[var(--green)]/5 ring-1 ring-[var(--green)]/30'
                          : 'bg-[var(--bg-0)] hover:bg-[var(--bg-3)]'
                      }`}
                    >
                      <div className="flex gap-2 mb-2.5">
                        <span className="w-6 h-6 rounded-sm border border-[var(--t4)]" style={{ background: t.bg }} />
                        <span className="w-6 h-6 rounded-sm" style={{ background: t.accent }} />
                      </div>
                      <p className={`text-[12px] ${theme === t.id ? 'text-[var(--green)]' : 'text-[var(--t2)]'}`}>{t.name}</p>
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase">Cỡ chữ</Label>
                <div className="flex gap-3">
                  {fontSizes.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => setFontSize(s.id)}
                      className={`px-5 py-2.5 rounded-md text-[13px] font-medium transition-all ${
                        fontSize === s.id
                          ? 'bg-[var(--green)]/15 text-[var(--green)] ring-1 ring-[var(--green)]/25'
                          : 'bg-[var(--bg-3)] text-[var(--t3)] hover:text-[var(--t2)] hover:bg-[var(--bg-4)]'
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <Label className="text-[11px] text-[var(--t3)] font-semibold tracking-widest uppercase">Ngôn ngữ Agent</Label>
                <div className="flex gap-3">
                  {languages.map((l) => (
                    <button
                      key={l.id}
                      onClick={() => setLanguage(l.id)}
                      className={`px-5 py-2.5 rounded-md text-[13px] font-medium transition-all ${
                        language === l.id
                          ? 'bg-[var(--green)]/15 text-[var(--green)] ring-1 ring-[var(--green)]/25'
                          : 'bg-[var(--bg-3)] text-[var(--t3)] hover:text-[var(--t2)] hover:bg-[var(--bg-4)]'
                      }`}
                    >
                      {l.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter className="border-[var(--bd)] bg-[var(--bg-3)]/50 px-7 py-5">
          <Button
            variant="ghost"
            onClick={() => onOpenChange(false)}
            className="text-[var(--t3)] hover:text-[var(--t2)] hover:bg-[var(--bg-4)] px-6 h-10"
          >
            Hủy
          </Button>
          <Button
            onClick={save}
            className="bg-[var(--green)] text-black hover:bg-[var(--green-dim)] font-bold px-7 h-10"
          >
            {saved ? 'Đã lưu ✓' : 'Lưu cài đặt'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
