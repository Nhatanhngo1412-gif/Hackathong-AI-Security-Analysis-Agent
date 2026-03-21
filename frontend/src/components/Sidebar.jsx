import { useState, useCallback } from 'react';
import { Upload, Search, RefreshCw, FileCode2, Cpu } from 'lucide-react';
import { uploadFile, getProcesses } from '@/api';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const T = {
  vi: { files: 'Tệp tin', processes: 'Tiến trình', dragDrop: 'Kéo thả hoặc nhấn để chọn', uploading: 'Đang tải lên...', noFiles: 'Chưa có tệp nào', search: 'Tìm kiếm...' },
  en: { files: 'Files', processes: 'Processes', dragDrop: 'Drag & drop or click to select', uploading: 'Uploading...', noFiles: 'No files yet', search: 'Search...' },
};

export default function Sidebar({ activeFile, setActiveFile, activePid, setActivePid, sidebarTab, setSidebarTab, lang = 'vi' }) {
  const t = T[lang] || T.vi;
  const [files, setFiles] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [processFilter, setProcessFilter] = useState('');
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const handleUpload = useCallback(async (fileList) => {
    for (const file of fileList) {
      setLoading(true);
      try {
        const result = await uploadFile(file);
        setFiles((prev) => [result, ...prev]);
        setActiveFile(result);
      } catch (e) { console.error(e); }
      setLoading(false);
    }
  }, [setActiveFile]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files.length > 0) handleUpload(e.dataTransfer.files);
  }, [handleUpload]);

  const refreshProcesses = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getProcesses(processFilter || undefined);
      setProcesses(data.processes || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, [processFilter]);

  return (
    <aside className="w-64 bg-[var(--bg-1)] border-r border-[var(--bd)] flex flex-col shrink-0 xl:w-72">
      <Tabs value={sidebarTab} onValueChange={(v) => { setSidebarTab(v); if (v === 'processes') refreshProcesses(); }} className="flex flex-col flex-1 min-h-0">
        <TabsList className="w-full rounded-none border-b border-[var(--bd)] bg-transparent h-auto p-0">
          <TabsTrigger
            value="files"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-[var(--green-glow)] data-[state=active]:shadow-none bg-transparent text-[var(--t3)] py-2.5 text-[12px] font-semibold gap-1.5"
          >
            <FileCode2 className="w-3.5 h-3.5" /> {t.files}
          </TabsTrigger>
          <TabsTrigger
            value="processes"
            className="flex-1 rounded-none border-b-2 border-transparent data-[state=active]:border-[var(--green)] data-[state=active]:text-[var(--green)] data-[state=active]:bg-[var(--green-glow)] data-[state=active]:shadow-none bg-transparent text-[var(--t3)] py-2.5 text-[12px] font-semibold gap-1.5"
          >
            <Cpu className="w-3.5 h-3.5" /> {t.processes}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="files" className="flex-1 flex flex-col min-h-0 mt-0">
          <div
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            className={`m-3 border-2 border-dashed rounded-lg p-5 text-center cursor-pointer transition-all ${
              dragOver
                ? 'border-[var(--green)] bg-[var(--green-glow)] scale-[1.01]'
                : 'border-[var(--t4)] hover:border-[var(--t3)] hover:bg-[var(--bg-2)]'
            }`}
          >
            <input type="file" className="hidden" id="file-upload" accept=".exe,.dll,.sys,.ocx,.scr,.bin" multiple onChange={(e) => handleUpload(e.target.files)} />
            <label htmlFor="file-upload" className="cursor-pointer">
              <Upload className={`w-6 h-6 mx-auto mb-2 ${dragOver ? 'text-[var(--green)]' : 'text-[var(--t4)]'}`} />
              <p className="text-[12px] text-[var(--t2)]">{t.dragDrop}</p>
              <p className="text-[10px] text-[var(--t4)] mt-1">.exe .dll .sys .ocx .scr .bin</p>
            </label>
          </div>

          {loading && (
            <div className="flex items-center gap-2 px-4 py-2 text-[12px] text-[var(--green)]">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" /> {t.uploading}
            </div>
          )}

          <ScrollArea className="flex-1 px-2 pb-2">
            {files.map((f) => {
              const active = activeFile?.file_id === f.file_id;
              return (
                <button
                  key={f.file_id}
                  onClick={() => setActiveFile(f)}
                  className={`w-full text-left px-3 py-2.5 rounded-lg mb-1 transition-all ${
                    active
                      ? 'bg-[var(--green-glow)] border border-[var(--green)]/20 accent-line'
                      : 'hover:bg-[var(--bg-3)] border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <FileCode2 className={`w-4 h-4 shrink-0 ${active ? 'text-[var(--green)]' : 'text-[var(--t4)]'}`} />
                    <span className={`text-[12px] truncate font-medium ${active ? 'text-[var(--green)]' : 'text-[var(--t2)]'}`}>
                      {f.file_name}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-1 ml-6">
                    <span className="text-[10px] text-[var(--t4)]">{(f.size / 1024).toFixed(1)} KB</span>
                    {f.quick_info?.file_type && (
                      <Badge className="text-[9px] px-1.5 py-0 bg-[var(--purple)]/10 text-[var(--purple)] border-[var(--purple)]/15 hover:bg-[var(--purple)]/15">
                        {f.quick_info.file_type}
                      </Badge>
                    )}
                  </div>
                </button>
              );
            })}
            {files.length === 0 && !loading && (
              <p className="text-[12px] text-[var(--t4)] text-center py-6">{t.noFiles}</p>
            )}
          </ScrollArea>
        </TabsContent>

        <TabsContent value="processes" className="flex-1 flex flex-col min-h-0 mt-0">
          <div className="flex gap-1.5 p-3">
            <div className="flex-1 relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--t4)]" />
              <input
                type="text"
                placeholder={t.search}
                value={processFilter}
                onChange={(e) => setProcessFilter(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && refreshProcesses()}
                className="w-full bg-[var(--bg-2)] border border-[var(--bd)] rounded-md pl-8 pr-3 py-2 text-[12px] text-[var(--t1)] placeholder:text-[var(--t4)] focus:outline-none focus:border-[var(--green)]/40 transition-colors"
              />
            </div>
            <Button
              variant="outline"
              size="icon"
              onClick={refreshProcesses}
              className="h-9 w-9 bg-[var(--bg-2)] border-[var(--bd)] hover:border-[var(--t3)] hover:bg-[var(--bg-3)]"
            >
              <RefreshCw className={`w-4 h-4 text-[var(--t3)] ${loading ? 'animate-spin text-[var(--green)]' : ''}`} />
            </Button>
          </div>

          <ScrollArea className="flex-1 px-2 pb-2">
            {processes.slice(0, 150).map((p) => {
              const active = activePid === p.pid;
              return (
                <button
                  key={p.pid}
                  onClick={() => setActivePid(p.pid)}
                  className={`w-full text-left px-3 py-2 rounded-lg mb-0.5 transition-all ${
                    active
                      ? 'bg-[var(--yellow)]/8 border border-[var(--yellow)]/20'
                      : 'hover:bg-[var(--bg-3)] border border-transparent'
                  }`}
                >
                  <div className="flex justify-between items-center">
                    <span className={`text-[12px] truncate font-medium ${active ? 'text-[var(--yellow)]' : 'text-[var(--t2)]'}`}>
                      {p.name}
                    </span>
                    <span className="text-[10px] text-[var(--t4)] ml-2 shrink-0 tabular-nums">{p.pid}</span>
                  </div>
                  <span className="text-[10px] text-[var(--t4)] tabular-nums">{p.memory_mb} MB</span>
                </button>
              );
            })}
          </ScrollArea>
        </TabsContent>
      </Tabs>
    </aside>
  );
}
