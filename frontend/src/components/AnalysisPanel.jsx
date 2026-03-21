import { useMemo } from 'react';
import { AlertTriangle, Check, X as XIcon, BarChart3, Code, Shield, Eye } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';

const T = {
  vi: {
    overview: 'Tổng quan', sections: 'Sections', security: 'Bảo mật',
    riskLabel: 'ĐÁNH GIÁ RỦI RO', danger: 'NGUY HIỂM', medium: 'TRUNG BÌNH', safe: 'AN TOÀN',
    fileType: 'Loại file', arch: 'Kiến trúc', system: 'Hệ thống', isDll: 'Là DLL', isDriver: 'Là Driver',
    yes: 'Có', no: 'Không', imports: 'IMPORTS', warnings: 'CẢNH BÁO',
    size: 'Kích thước', on: 'BẬT', off: 'TẮT', noData: 'Không có dữ liệu',
    uploadPrompt: 'Tải tệp lên để xem chi tiết phân tích',
  },
  en: {
    overview: 'Overview', sections: 'Sections', security: 'Security',
    riskLabel: 'RISK ASSESSMENT', danger: 'DANGER', medium: 'MEDIUM', safe: 'SAFE',
    fileType: 'File type', arch: 'Architecture', system: 'Subsystem', isDll: 'Is DLL', isDriver: 'Is Driver',
    yes: 'Yes', no: 'No', imports: 'IMPORTS', warnings: 'WARNINGS',
    size: 'Size', on: 'ON', off: 'OFF', noData: 'No data',
    uploadPrompt: 'Upload a file to view analysis details',
  },
};

export default function AnalysisPanel({ events, activeFile, lang = 'vi' }) {
  const t = T[lang] || T.vi;
  const peInfo = useMemo(() => {
    if (activeFile?.quick_info && !activeFile.quick_info.error) return activeFile.quick_info;
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === 'tool_result' && events[i].tool === 'analyze_pe_file' && !events[i].result?.error)
        return events[i].result;
    }
    return null;
  }, [events, activeFile]);

  const sections = useMemo(() => {
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].type === 'tool_result' && events[i].tool === 'get_sections_overview' && events[i].result?.sections)
        return events[i].result.sections;
    }
    return peInfo?.sections || [];
  }, [events, peInfo]);

  const score = useMemo(() => {
    if (!peInfo) return null;
    let s = (peInfo.suspicious_indicators?.length || 0) * 10;
    const f = peInfo.security_flags || {};
    if (!f.ASLR) s += 10;
    if (!f['DEP/NX']) s += 10;
    if (!f.CFG) s += 5;
    return Math.min(s, 100);
  }, [peInfo]);

  return (
    <div className="w-80 bg-[var(--bg-1)] flex flex-col shrink-0 xl:w-96 border-l border-[var(--bd)]">
      <Tabs defaultValue="overview" className="flex flex-col flex-1 min-h-0">
        <TabsList className="w-full rounded-none border-b border-[var(--bd)] bg-transparent h-auto p-0">
          <TabsTrigger
            value="overview"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-[var(--green-glow)] data-[state=active]:shadow-none bg-transparent text-[var(--t3)] py-2.5 text-[11px] font-semibold gap-1.5"
          >
            <BarChart3 className="w-3.5 h-3.5" /> {t.overview}
          </TabsTrigger>
          <TabsTrigger
            value="sections"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-[var(--green-glow)] data-[state=active]:shadow-none bg-transparent text-[var(--t3)] py-2.5 text-[11px] font-semibold gap-1.5"
          >
            <Code className="w-3.5 h-3.5" /> Sections
          </TabsTrigger>
          <TabsTrigger
            value="security"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-[var(--green-glow)] data-[state=active]:shadow-none bg-transparent text-[var(--t3)] py-2.5 text-[11px] font-semibold gap-1.5"
          >
            <Shield className="w-3.5 h-3.5" /> {t.security}
          </TabsTrigger>
        </TabsList>

        {!peInfo ? (
          <div className="flex-1 flex flex-col items-center justify-center text-center p-6">
            <Eye className="w-8 h-8 text-[var(--t4)] mb-2" />
            <p className="text-[12px] text-[var(--t4)]">{t.uploadPrompt}</p>
          </div>
        ) : (
          <>
            <TabsContent value="overview" className="flex-1 mt-0 min-h-0">
              <ScrollArea className="h-full">
                <div className="p-3 space-y-3 fade-in">
                  {score !== null && (
                    <Card className="bg-[var(--bg-2)] border-[var(--bd)] p-3.5">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[11px] text-[var(--t3)] font-semibold tracking-wide">{t.riskLabel}</span>
                        <Badge className={`text-[11px] font-bold ${
                          score > 70 ? 'bg-[var(--red)]/10 text-[var(--red)] border-[var(--red)]/20' :
                          score > 40 ? 'bg-[var(--yellow)]/10 text-[var(--yellow)] border-[var(--yellow)]/20' :
                          'bg-[var(--green)]/10 text-[var(--green)] border-[var(--green)]/20'
                        }`}>
                          {score > 70 ? t.danger : score > 40 ? t.medium : t.safe}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`text-2xl font-black tabular-nums ${
                          score > 70 ? 'text-[var(--red)]' : score > 40 ? 'text-[var(--yellow)]' : 'text-[var(--green)]'
                        }`}>{score}</span>
                        <div className="flex-1">
                          <div className="h-2 bg-[var(--bg-0)] rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{
                                width: `${score}%`,
                                background: score > 70 ? 'var(--red)' : score > 40 ? 'var(--yellow)' : 'var(--green)',
                              }}
                            />
                          </div>
                          <div className="flex justify-between text-[9px] text-[var(--t4)] mt-1 tabular-nums">
                            <span>0</span><span>50</span><span>100</span>
                          </div>
                        </div>
                      </div>
                    </Card>
                  )}

                  <Card className="bg-[var(--bg-2)] border-[var(--bd)] overflow-hidden">
                    <InfoRow label={t.fileType} value={peInfo.file_type} color="var(--purple)" />
                    <InfoRow label={t.arch} value={peInfo.machine} />
                    <InfoRow label={t.system} value={peInfo.subsystem} />
                    <InfoRow label="Entry Point" value={peInfo.entry_point} mono />
                    <InfoRow label="Image Base" value={peInfo.image_base} mono />
                    <InfoRow label={t.isDll} value={peInfo.is_dll ? t.yes : t.no} />
                    <InfoRow label={t.isDriver} value={peInfo.is_driver ? t.yes : t.no} last />
                  </Card>

                  {peInfo.imports?.length > 0 && (
                    <Card className="bg-[var(--bg-2)] border-[var(--bd)] p-3">
                      <p className="text-[11px] text-[var(--t3)] font-semibold tracking-wide mb-2">
                        IMPORTS <span className="text-[var(--blue)]">({peInfo.imports.length})</span>
                      </p>
                      <div className="max-h-36 overflow-y-auto space-y-0.5">
                        {peInfo.imports.map((imp, i) => (
                          <div key={i} className="flex justify-between text-[11px] py-0.5 hover:bg-[var(--bg-3)] px-1 rounded">
                            <span className="text-[var(--blue)] truncate">{imp.dll}</span>
                            <span className="text-[var(--t4)] shrink-0 ml-2 tabular-nums">{imp.functions.length} funcs</span>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {peInfo.suspicious_indicators?.length > 0 && (
                    <Card className="bg-[var(--red-glow)] border-[var(--red)]/15 p-3">
                      <p className="text-[11px] text-[var(--red)] font-semibold tracking-wide mb-2 flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4" />
                        {t.warnings} ({peInfo.suspicious_indicators.length})
                      </p>
                      <div className="space-y-1">
                        {peInfo.suspicious_indicators.map((s, i) => (
                          <p key={i} className="text-[11px] text-[var(--red)]/80 leading-relaxed pl-1 border-l-2 border-[var(--red)]/20 ml-0.5">{s}</p>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="sections" className="flex-1 mt-0 min-h-0">
              <ScrollArea className="h-full">
                <div className="p-3 space-y-2 fade-in">
                  {sections.map((s, i) => (
                    <Card key={i} className="bg-[var(--bg-2)] border-[var(--bd)] p-3">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-[12px] font-bold text-[var(--blue)]">{s.name}</span>
                        <div className="flex gap-1">
                          {s.is_executable && <Badge className="text-[9px] px-1.5 py-0 bg-[var(--red)]/10 text-[var(--red)] border-[var(--red)]/20">EXEC</Badge>}
                          {s.is_writable && <Badge className="text-[9px] px-1.5 py-0 bg-[var(--yellow)]/10 text-[var(--yellow)] border-[var(--yellow)]/20">WRITE</Badge>}
                          {s.packed_likely && <Badge className="text-[9px] px-1.5 py-0 bg-[var(--purple)]/10 text-[var(--purple)] border-[var(--purple)]/20">PACKED</Badge>}
                        </div>
                      </div>
                      <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[11px]">
                        <span className="text-[var(--t4)]">VA</span>
                        <span className="text-[var(--t2)] font-mono">{s.virtual_address}</span>
                        <span className="text-[var(--t4)]">{t.size}</span>
                        <span className="text-[var(--t2)]">{(s.raw_size / 1024).toFixed(1)} KB</span>
                        <span className="text-[var(--t4)]">Entropy</span>
                        <span className={`font-mono font-bold ${s.entropy > 7 ? 'text-[var(--red)]' : s.entropy > 6 ? 'text-[var(--yellow)]' : 'text-[var(--green)]'}`}>
                          {s.entropy} / 8.0
                        </span>
                      </div>
                      <div className="h-1.5 bg-[var(--bg-0)] rounded-full mt-2 overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${(s.entropy / 8) * 100}%`,
                            background: s.entropy > 7 ? 'var(--red)' : s.entropy > 6 ? 'var(--yellow)' : 'var(--green)',
                          }}
                        />
                      </div>
                    </Card>
                  ))}
                  {sections.length === 0 && <p className="text-[12px] text-[var(--t4)] text-center py-8">{t.noData}</p>}
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="security" className="flex-1 mt-0 min-h-0">
              <ScrollArea className="h-full">
                <div className="p-3 space-y-1.5 fade-in">
                  {Object.entries(peInfo.security_flags || {}).map(([key, val]) => (
                    <Card key={key} className="flex items-center justify-between bg-[var(--bg-2)] border-[var(--bd)] px-3.5 py-2.5">
                      <span className="text-[12px] text-[var(--t2)]">{key}</span>
                      {val ? (
                        <Badge className="bg-[var(--green)]/10 text-[var(--green)] border-[var(--green)]/20 text-[11px] font-semibold gap-1">
                          <Check className="w-3.5 h-3.5" /> {t.on}
                        </Badge>
                      ) : (
                        <Badge className="bg-[var(--red)]/10 text-[var(--red)] border-[var(--red)]/20 text-[11px] font-semibold gap-1">
                          <XIcon className="w-3.5 h-3.5" /> {t.off}
                        </Badge>
                      )}
                    </Card>
                  ))}
                </div>
              </ScrollArea>
            </TabsContent>
          </>
        )}
      </Tabs>
    </div>
  );
}

function InfoRow({ label, value, mono, color, last }) {
  return (
    <div className={`flex justify-between px-3.5 py-2 ${last ? '' : 'border-b border-[var(--bd)]'} hover:bg-[var(--bg-3)] transition-colors`}>
      <span className="text-[11px] text-[var(--t3)]">{label}</span>
      <span className={`text-[11px] truncate ml-3 text-right ${mono ? 'font-mono' : 'font-medium'}`} style={{ color: color || 'var(--t2)' }}>
        {value || '—'}
      </span>
    </div>
  );
}
