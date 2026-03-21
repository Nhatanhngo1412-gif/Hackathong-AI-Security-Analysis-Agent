import { useState, useEffect } from 'react';
import TitleBar from './components/TitleBar';
import Sidebar from './components/Sidebar';
import ChatPanel from './components/ChatPanel';
import AnalysisPanel from './components/AnalysisPanel';
import Header from './components/Header';
import { TooltipProvider } from '@/components/ui/tooltip';
import { getHealth } from './api';

export default function App() {
  const [activeFile, setActiveFile] = useState(null);
  const [activePid, setActivePid] = useState(null);
  const [sessionId, setSessionId] = useState(null);
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);
  const [sidebarTab, setSidebarTab] = useState('files');
  const [healthInfo, setHealthInfo] = useState(null);
  const [lang, setLang] = useState(() => localStorage.getItem('app-lang') || 'vi');

  useEffect(() => {
    const check = () =>
      getHealth()
        .then((h) => { setConnected(h.status === 'ok'); setHealthInfo(h); })
        .catch(() => setConnected(false));
    check();
    const iv = setInterval(check, 15000);
    return () => clearInterval(iv);
  }, []);

  const handleNewAnalysis = (newEvents, newSessionId) => {
    setEvents((prev) => {
      let updated = [...prev];
      for (const ev of newEvents) {
        if (ev.type === 'message_delta') {
          const last = updated[updated.length - 1];
          if (last && last._streaming) {
            updated = [...updated.slice(0, -1), { ...last, content: last.content + ev.content }];
          } else {
            updated.push({ type: 'message', content: ev.content, _streaming: true });
          }
        } else if (ev.type === 'content_done' && ev.role === 'thinking') {
          const last = updated[updated.length - 1];
          if (last && last._streaming) {
            updated = [...updated.slice(0, -1), { type: 'thinking', content: last.content }];
          }
        } else if (ev.type === 'message_end') {
          const last = updated[updated.length - 1];
          if (last && last._streaming) {
            updated = [...updated.slice(0, -1), { type: 'message', content: last.content }];
          }
        } else if (ev.type === 'thinking_start') {
          // skip - visual only, handled by loading state
        } else {
          updated.push(ev);
        }
      }
      return updated;
    });
    if (newSessionId) setSessionId(newSessionId);
  };

  const handleClearChat = () => {
    setEvents([]);
    setSessionId(null);
  };

  return (
    <TooltipProvider delayDuration={300}>
      <div className="h-screen flex flex-col overflow-hidden bg-[var(--bg-0)]">
        <TitleBar />
        <Header
          connected={connected}
          healthInfo={healthInfo}
          activeFile={activeFile}
          activePid={activePid}
          lang={lang}
          setLang={(l) => { setLang(l); localStorage.setItem('app-lang', l); }}
        />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar
            activeFile={activeFile}
            setActiveFile={setActiveFile}
            activePid={activePid}
            setActivePid={setActivePid}
            sidebarTab={sidebarTab}
            setSidebarTab={setSidebarTab}
            lang={lang}
          />
          <main className="flex flex-1 overflow-hidden">
            <ChatPanel
              sessionId={sessionId}
              events={events}
              activeFile={activeFile}
              activePid={activePid}
              onNewAnalysis={handleNewAnalysis}
              onClear={handleClearChat}
              lang={lang}
            />
            <AnalysisPanel events={events} activeFile={activeFile} lang={lang} />
          </main>
        </div>
      </div>
    </TooltipProvider>
  );
}
