const BASE = '/api';

export async function uploadFile(file) {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(`${BASE}/upload`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export async function sendChatStream(sessionId, message, filePath, pid, onEvent) {
  const res = await fetch(`${BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      session_id: sessionId || undefined,
      message,
      file_path: filePath || undefined,
      pid: pid || undefined,
    }),
  });
  if (!res.ok) throw new Error(await res.text());

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const lines = buffer.split('\n');
    buffer = lines.pop();

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('data: ')) {
        try {
          const event = JSON.parse(trimmed.slice(6));
          onEvent(event);
        } catch {}
      }
    }
  }

  if (buffer.trim().startsWith('data: ')) {
    try {
      onEvent(JSON.parse(buffer.trim().slice(6)));
    } catch {}
  }
}

export async function clearChat(sessionId) {
  await fetch(`${BASE}/chat/clear?session_id=${sessionId}`, { method: 'POST' });
}

export async function getProcesses(name) {
  const url = name ? `${BASE}/processes?name=${encodeURIComponent(name)}` : `${BASE}/processes`;
  return (await fetch(url)).json();
}

export async function getProcessInfo(pid) {
  return (await fetch(`${BASE}/processes/${pid}`)).json();
}

export async function getHealth() {
  return (await fetch(`${BASE}/health`)).json();
}

export async function getUploadedFiles() {
  return (await fetch(`${BASE}/files`)).json();
}

export async function getSettings() {
  return (await fetch(`${BASE}/settings`)).json();
}

export async function updateSettings(settings) {
  const res = await fetch(`${BASE}/settings`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  });
  return res.json();
}
