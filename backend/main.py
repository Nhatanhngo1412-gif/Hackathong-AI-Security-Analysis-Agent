"""
1337APP Backend - AI Security Analysis Agent
FastAPI server serving API + static React frontend
"""

import os
import uuid
import json
import shutil
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Optional

from . import config
from .agent.core import AgentCore
from .tools.process_manager import ProcessManager
from .tools.pe_analyzer import PEAnalyzer

app = FastAPI(title="AI Security Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent = AgentCore()


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str
    file_path: Optional[str] = None
    pid: Optional[int] = None


class ChatResponse(BaseModel):
    session_id: str
    events: list


class SettingsRequest(BaseModel):
    api_key: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "api_key_set": bool(config.OPENAI_API_KEY),
        "model": config.OPENAI_MODEL,
        "base_url": config.OPENAI_BASE_URL or "https://api.openai.com/v1",
        "version": "1.0.0",
    }


@app.get("/api/settings")
async def get_settings():
    key = config.OPENAI_API_KEY
    masked = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else "not set"
    return {
        "api_key_masked": masked,
        "model": config.OPENAI_MODEL,
        "base_url": config.OPENAI_BASE_URL or "",
    }


@app.post("/api/settings")
async def update_settings(req: SettingsRequest):
    global agent
    if req.api_key is not None:
        config.OPENAI_API_KEY = req.api_key
    if req.model is not None:
        config.OPENAI_MODEL = req.model
    if req.base_url is not None:
        config.OPENAI_BASE_URL = req.base_url

    agent = AgentCore()
    return {"status": "updated", "model": config.OPENAI_MODEL}


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    file_id = str(uuid.uuid4())[:8]
    safe_name = file.filename.replace(" ", "_").replace("..", "")
    save_path = os.path.join(config.UPLOAD_DIR, f"{file_id}_{safe_name}")

    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    quick_info = {}
    if save_path.lower().endswith((".exe", ".dll", ".sys", ".ocx", ".scr")):
        try:
            quick_info = PEAnalyzer.analyze_file(save_path)
        except Exception:
            pass

    return {
        "file_id": file_id,
        "file_name": file.filename,
        "file_path": save_path,
        "size": os.path.getsize(save_path),
        "quick_info": quick_info,
    }


@app.post("/api/chat")
async def chat(req: ChatRequest):
    if not config.OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API key not configured")

    session_id = req.session_id or str(uuid.uuid4())

    context = {}
    if req.file_path:
        context["file_path"] = req.file_path
    if req.pid:
        context["pid"] = req.pid

    def event_stream():
        yield f"data: {json.dumps({'type': 'session', 'session_id': session_id})}\n\n"
        for event in agent.analyze_stream(session_id, req.message, context if context else None):
            yield f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/chat/clear")
async def clear_chat(session_id: str = None):
    if session_id:
        agent.clear_conversation(session_id)
    return {"status": "cleared"}


@app.get("/api/processes")
async def get_processes(name: Optional[str] = None):
    return ProcessManager.list_processes(name)


@app.get("/api/processes/{pid}")
async def get_process(pid: int):
    return ProcessManager.get_process_info(pid)


@app.get("/api/files")
async def list_uploaded_files():
    files = []
    for f in os.listdir(config.UPLOAD_DIR):
        fpath = os.path.join(config.UPLOAD_DIR, f)
        if os.path.isfile(fpath):
            files.append({
                "name": f,
                "path": fpath,
                "size": os.path.getsize(fpath),
            })
    return {"files": files}


FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")

if os.path.exists(FRONTEND_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        file_path = os.path.join(FRONTEND_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
