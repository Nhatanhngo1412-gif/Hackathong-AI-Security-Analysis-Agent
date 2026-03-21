import { useState, useRef, useEffect, useCallback } from 'react';
import { Send, AlertCircle, Loader2, Shield, ChevronDown, ChevronRight, Wrench, Brain } from 'lucide-react';
import { sendChatStream, clearChat } from '@/api';
import Markdown from 'react-markdown';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

const T = {
  vi: {
    ready: 'sẵn sàng',
    subtitle: 'Tải file hoặc chọn PID, sau đó nhập prompt để bắt đầu phân tích.',
    placeholder: 'Nhập câu hỏi phân tích bảo mật...',
    processing: 'Agent đang xử lý...',
    toolSteps: 'bước phân tích',
    toolError: 'lỗi',
    viewResult: 'xem kết quả',
  },
  en: {
    ready: 'ready',
    subtitle: 'Upload a file or select a PID, then type your prompt to start analysis.',
    placeholder: 'Ask a security analysis question...',
    processing: 'Agent processing...',
    toolSteps: 'analysis steps',
    toolError: 'error',
    viewResult: 'view result',
  },
};

export default function ChatPanel({ sessionId, events, activeFile, activePid, onNewAnalysis, onClear, lang = 'vi' }) {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);
  const inputRef = useRef(null);
  const t = T[lang] || T.vi;

  const scrollToBottom = useCallback(() => {
    const el = scrollRef.current;
    if (el) requestAnimationFrame(() => { el.scrollTop = el.scrollHeight; });
  }, []);

  useEffect(() => { scrollToBottom(); }, [events, loading, scrollToBottom]);

  const send = async () => {
    if (!input.trim() || loading) return;
    const msg = input.trim();
    setInput('');
    onNewAnalysis([{ type: 'user_message', content: msg }], sessionId);
    setLoading(true);
    try {
      await sendChatStream(sessionId, msg, activeFile?.file_path, activePid, (event) => {
        if (event.type === 'session') {
          onNewAnalysis([], event.session_id);
        } else if (event.type === 'done') {
          setLoading(false);
        } else {
          onNewAnalysis([event]);
        }
      });
    } catch (e) {
      onNewAnalysis([{ type: 'error', content: e.message }]);
    }
    setLoading(false);
    inputRef.current?.focus();
  };

  const grouped = groupEvents(events);

  return (
    <div className="flex-1 flex flex-col min-w-0 bg-[var(--bg-0)]">
      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto">
        <div className="max-w-3xl mx-auto px-5 py-6">
          {events.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 fade-in select-none">
              <div className="w-16 h-16 rounded-full bg-[var(--green)]/10 border-2 border-[var(--green)]/20 flex items-center justify-center mb-5">
                <Shield className="w-7 h-7 text-[var(--green)]" />
              </div>
              <p className="text-[20px] text-[var(--t1)] font-bold">
                AI <span className="text-[var(--green)]">Security</span> Agent {t.ready}
              </p>
              <p className="text-[13px] text-[var(--t3)] mt-2 text-center max-w-md leading-6">{t.subtitle}</p>
            </div>
          )}

          <div className="space-y-5">
            {grouped.map((g, i) => <GroupedEvent key={i} group={g} t={t} />)}
          </div>

          {loading && !events.some(e => e._streaming) && (
            <div className="flex items-center gap-2.5 mt-5 fade-in">
              <Loader2 className="w-4 h-4 text-[var(--green)] animate-spin" />
              <span className="text-[13px] text-[var(--t3)]">{t.processing}</span>
            </div>
          )}
        </div>
      </div>

      {/* Input */}
      <div className="border-t border-[var(--bd)] bg-[var(--bg-1)] shrink-0">
        <div className="max-w-3xl mx-auto px-5 py-3">
          <div className="flex items-end gap-3">
            <div className="flex-1 relative">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    send();
                  }
                }}
                placeholder={t.placeholder}
                rows={1}
                className="w-full resize-none rounded-2xl border border-[var(--bd)] bg-[var(--bg-2)] pl-5 pr-5 py-3.5 text-[14px] leading-6 text-[var(--t1)] placeholder:text-[var(--t4)] focus:outline-none focus:border-[var(--green)]/30 transition-colors min-h-[48px] max-h-40"
                style={{ fieldSizing: 'content' }}
              />
            </div>
            <button
              onClick={send}
              disabled={loading || !input.trim()}
              className="w-11 h-11 rounded-xl bg-[var(--green)] hover:bg-[var(--green-dim)] disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center transition-colors shrink-0"
            >
              <Send className="w-4.5 h-4.5 text-black" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function groupEvents(events) {
  const groups = [];
  let currentToolGroup = null;

  for (const ev of events) {
    if (ev.type === 'tool_call' || ev.type === 'tool_result') {
      if (!currentToolGroup) {
        currentToolGroup = { type: 'tool_group', items: [] };
        groups.push(currentToolGroup);
      }
      currentToolGroup.items.push(ev);
    } else {
      currentToolGroup = null;
      groups.push(ev);
    }
  }
  return groups;
}

function GroupedEvent({ group, t }) {
  if (group.type === 'tool_group') return <ToolGroup items={group.items} t={t} />;
  return <SingleEvent ev={group} t={t} />;
}

function SingleEvent({ ev }) {
  if (ev.type === 'user_message') {
    return (
      <div className="flex justify-end fade-in">
        <div className="max-w-[80%] bg-[var(--bg-3)] rounded-2xl rounded-br-md px-5 py-3.5">
          <p className="text-[14px] text-[var(--t1)] leading-7 whitespace-pre-wrap">{ev.content}</p>
        </div>
      </div>
    );
  }

  if (ev.type === 'thinking') {
    return (
      <div className="flex items-start gap-2.5 fade-in py-1">
        <Brain className="w-4 h-4 text-[var(--purple)] shrink-0 mt-0.5" />
        <p className="text-[13px] text-[var(--t2)] italic leading-6">{ev.content}</p>
      </div>
    );
  }

  if (ev.type === 'message') {
    return (
      <div className="fade-in text-[14px] text-[var(--t1)] prose-agent leading-7">
        <Markdown>{ev.content}</Markdown>
        {ev._streaming && <span className="inline-block w-1.5 h-5 bg-[var(--green)] rounded-sm ml-0.5 animate-pulse align-middle" />}
      </div>
    );
  }

  if (ev.type === 'error') {
    return (
      <div className="flex items-center gap-2.5 fade-in text-[13px] text-[var(--red)] bg-[var(--red-glow)] rounded-xl px-4 py-3 border border-[var(--red)]/10">
        <AlertCircle className="w-4 h-4 shrink-0" />
        {ev.content}
      </div>
    );
  }

  return null;
}

function ToolGroup({ items, t }) {
  const calls = items.filter(i => i.type === 'tool_call');
  const hasError = items.some(i => i.type === 'tool_result' && i.result?.error);

  return (
    <Collapsible className="fade-in">
      <CollapsibleTrigger className="group flex items-center gap-2 text-[13px] text-[var(--t3)] hover:text-[var(--t1)] cursor-pointer select-none py-1 transition-colors">
        <Wrench className="w-3.5 h-3.5 text-[var(--yellow)]" />
        <span className="font-medium">{calls.length} {t.toolSteps}</span>
        {hasError && <span className="text-[var(--red)] text-[11px]">({t.toolError})</span>}
        <ChevronRight className="w-3.5 h-3.5 text-[var(--t4)] group-data-[state=open]:hidden" />
        <ChevronDown className="w-3.5 h-3.5 text-[var(--t4)] hidden group-data-[state=open]:block" />
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div className="mt-1.5 space-y-1 border-l-2 border-[var(--bd)] pl-4 ml-0.5">
          {items.map((item, i) => {
            if (item.type === 'tool_call') {
              return (
                <div key={i} className="text-[12px] text-[var(--t2)] leading-6 py-0.5">
                  <span className="text-[var(--yellow)] font-medium">{item.tool}</span>
                  <span className="text-[var(--t4)]">(</span>
                  <span className="text-[var(--t3)]">
                    {Object.entries(item.args || {}).map(([k, v]) => {
                      const val = typeof v === 'string' ? (v.length > 40 ? `"${v.slice(0, 40)}..."` : `"${v}"`) : JSON.stringify(v);
                      return `${k}=${val}`;
                    }).join(', ')}
                  </span>
                  <span className="text-[var(--t4)]">)</span>
                </div>
              );
            }
            if (item.type === 'tool_result') {
              const err = item.result?.error;
              return (
                <Collapsible key={i}>
                  <CollapsibleTrigger className={`text-[11px] py-0.5 cursor-pointer select-none flex items-center gap-1 ${err ? 'text-[var(--red)]' : 'text-[var(--t4)]'} hover:text-[var(--t2)]`}>
                    {err ? '✗' : '✓'} <span className="text-[var(--yellow)]">{item.tool}</span>
                    <span className="text-[var(--t4)] ml-1">[{t.viewResult}]</span>
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <pre className="text-[11px] text-[var(--t3)] mt-1 p-3 bg-[var(--bg-2)] rounded-lg border border-[var(--bd)] overflow-x-auto max-h-40 overflow-y-auto font-mono leading-5">
                      {JSON.stringify(item.result, null, 2).slice(0, 4000)}
                    </pre>
                  </CollapsibleContent>
                </Collapsible>
              );
            }
            return null;
          })}
        </div>
      </CollapsibleContent>
    </Collapsible>
  );
}
