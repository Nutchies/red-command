from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from app.api import routes
from app.db.database import engine, Base, SessionLocal
from app.core.config import settings
from app.models.models import ChatMessage, User, ChatRoom
from sqlalchemy.orm import Session
from datetime import datetime
import os
import json
import asyncio

app = FastAPI(title="Red Team Command Center", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(routes.router, prefix="/api")

web_dir = os.path.join(os.path.dirname(__file__), "web")
if os.path.exists(web_dir):
    app.mount("/static", StaticFiles(directory=web_dir), name="static")


@app.get("/")
async def root():
    index_path = os.path.join(web_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "Expires": "0"})
    return {"message": "Red Team Command Center API", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}

    async def connect(self, websocket: WebSocket, room_id: str, user_id: int):
        await websocket.accept()
        if room_id not in self.active_connections:
            self.active_connections[room_id] = []
        self.active_connections[room_id].append({"websocket": websocket, "user_id": user_id})

    def disconnect(self, websocket: WebSocket, room_id: str):
        if room_id in self.active_connections:
            self.active_connections[room_id] = [
                conn for conn in self.active_connections[room_id]
                if conn["websocket"] != websocket
            ]
            if not self.active_connections[room_id]:
                del self.active_connections[room_id]

    async def broadcast(self, room_id: str, message: dict):
        if room_id in self.active_connections:
            for conn in self.active_connections[room_id]:
                try:
                    await conn["websocket"].send_json(message)
                except:
                    self.disconnect(conn["websocket"], room_id)


manager = ConnectionManager()


@app.websocket("/ws/chat/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: str, token: str = None):
    user_id = None
    if token:
        try:
            from jose import jwt
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            if username:
                db = SessionLocal()
                user = db.query(User).filter(User.username == username).first()
                if user:
                    user_id = user.id
                db.close()
        except:
            pass

    await manager.connect(websocket, room_id, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                message = json.loads(data)
                db = SessionLocal()
                user = db.query(User).filter(User.id == user_id).first() if user_id else None
                
                chat_msg = ChatMessage(
                    room_id=int(room_id),
                    user_id=user_id if user_id else 1,
                    content=message.get("content"),
                    message_type=message.get("message_type", "text"),
                    file_path=message.get("file_path"),
                    file_name=message.get("file_name"),
                    file_size=message.get("file_size", 0),
                    reply_to=message.get("reply_to")
                )
                db.add(chat_msg)
                db.commit()
                db.refresh(chat_msg)
                
                room = db.query(ChatRoom).filter(ChatRoom.id == int(room_id)).first()
                if room:
                    room.updated_at = datetime.now()
                    db.commit()
                
                reply_content = None
                reply_username = None
                if chat_msg.reply_to:
                    reply_msg = db.query(ChatMessage).filter(ChatMessage.id == chat_msg.reply_to).first()
                    if reply_msg:
                        reply_content = reply_msg.content[:50] + "..." if len(reply_msg.content) > 50 else reply_msg.content if reply_msg.content else ""
                        if reply_msg.user:
                            reply_username = reply_msg.user.username
                
                response = {
                    "id": chat_msg.id,
                    "room_id": chat_msg.room_id,
                    "user_id": chat_msg.user_id,
                    "username": user.username if user else "unknown",
                    "content": chat_msg.content,
                    "message_type": chat_msg.message_type,
                    "file_path": chat_msg.file_path,
                    "file_name": chat_msg.file_name,
                    "file_size": chat_msg.file_size,
                    "reply_to": chat_msg.reply_to,
                    "reply_content": reply_content,
                    "reply_username": reply_username,
                    "created_at": chat_msg.created_at.isoformat()
                }
                db.close()
                
                await manager.broadcast(room_id, response)
            except Exception as e:
                print(f"WebSocket message error: {e}")
    except WebSocketDisconnect:
        manager.disconnect(websocket, room_id)


if __name__ == "__main__":
    import subprocess
    import sys
    
    cert_dir = os.path.join(os.path.dirname(__file__), "cert")
    
    https_proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn",
        "main:app",
        "--host", "0.0.0.0",
        "--port", "8443",
        "--ssl-keyfile", os.path.join(cert_dir, "server.key"),
        "--ssl-certfile", os.path.join(cert_dir, "server.crt")
    ])
    
    try:
        https_proc.wait()
    except KeyboardInterrupt:
        https_proc.terminate()
        https_proc.wait()