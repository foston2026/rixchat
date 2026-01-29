import os
import jwt
import time
import uuid
import shutil
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Union

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, ForeignKey, Text, or_, and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---------------- CONFIG ----------------
SECRET_KEY = os.getenv("SECRET_KEY", "rixchat_super_secret_772211")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your-email@gmail.com"
SMTP_PASS = "your-app-password"

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO)

# ---------------- DATABASE ----------------
SQLALCHEMY_DATABASE_URL = "sqlite:///./rixchat.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    avatar = Column(String, default="/uploads/default.png")
    bio = Column(String, default="")
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_online = Column(Boolean, default=False)

class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    is_group = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Participant(Base):
    __tablename__ = "participants"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    chat_id = Column(Integer, ForeignKey("chats.id"))
    is_admin = Column(Boolean, default=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, ForeignKey("chats.id"))
    sender_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    msg_type = Column(String, default="text") # text, image
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

class BlockedUser(Base):
    __tablename__ = "blocked_users"
    id = Column(Integer, primary_key=True, index=True)
    blocker_id = Column(Integer, ForeignKey("users.id"))
    blocked_id = Column(Integer, ForeignKey("users.id"))

Base.metadata.create_all(bind=engine)

# ---------------- SECURITY ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# ---------------- EMAIL ----------------
def send_verification_email(email: str, token: str):
    message = MIMEMultipart()
    message["From"] = SMTP_USER
    message["To"] = email
    message["Subject"] = "Verify your RixChat account"
    body = f"Click to verify: https://yourdomain.com/verify?token={token}"
    message.attach(MIMEText(body, "plain"))
    # This is a mock, in production uncomment
    # with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
    #     server.starttls()
    #     server.login(SMTP_USER, SMTP_PASS)
    #     server.send_message(message)

# ---------------- REAL-TIME MANAGER ----------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        logging.info(f"User {user_id} connected, total connections: {len(self.active_connections[user_id])}")

    def disconnect(self, user_id: int, websocket: WebSocket):
        if user_id in self.active_connections:
            self.active_connections[user_id].remove(websocket)
            logging.info(f"User {user_id} disconnected")

    async def send_personal_message(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await connection.send_json(message)

    async def broadcast_to_chat(self, db: Session, chat_id: int, message: dict):
        participants = db.query(Participant).filter(Participant.chat_id == chat_id).all()
        for p in participants:
            await self.send_personal_message(message, p.user_id)

manager = ConnectionManager()

# ---------------- APP ----------------
app = FastAPI(title="RixChat API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

# ---------------- ROUTES ----------------
@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head>
            <title>RixChat</title>
        </head>
        <body>
            <h1>Добро пожаловать в RixChat API!</h1>
            <p>Используйте <code>/register</code> или <code>/login</code> для работы с API</p>
        </body>
    </html>
    """

@app.get("/favicon.ico")
async def favicon():
    path = os.path.join(UPLOAD_DIR, "favicon.ico")
    if os.path.exists(path):
        return FileResponse(path)
    return HTMLResponse("")

# ---------------- AUTH ----------------
@app.post("/register")
async def register(username: str = Form(...), email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    if db.query(User).filter(or_(User.username == username, User.email == email)).first():
        raise HTTPException(status_code=400, detail="User already exists")
    token = str(uuid.uuid4())
    new_user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        verification_token=token
    )
    db.add(new_user)
    db.commit()
    send_verification_email(email, token)
    return {"msg": "Registration successful. Please verify your email."}

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "username": user.username, "avatar": user.avatar}}

# ---------------- CHATS ----------------
@app.get("/chats")
async def get_chats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    chat_ids = db.query(Participant.chat_id).filter(Participant.user_id == current_user.id).all()
    ids = [c[0] for c in chat_ids]
    chats = db.query(Chat).filter(Chat.id.in_(ids)).all()
    results = []
    for chat in chats:
        last_msg = db.query(Message).filter(Message.chat_id == chat.id).order_by(Message.timestamp.desc()).first()
        other_user = None
        if not chat.is_group:
            other_p = db.query(Participant).filter(and_(Participant.chat_id == chat.id, Participant.user_id != current_user.id)).first()
            if other_p:
                other_user = db.query(User).filter(User.id == other_p.user_id).first()
        results.append({
            "id": chat.id,
            "name": chat.name if chat.is_group else (other_user.username if other_user else "Deleted User"),
            "avatar": other_user.avatar if other_user and not chat.is_group else "/uploads/group.png",
            "is_group": chat.is_group,
            "last_message": last_msg.content if last_msg else "",
            "last_time": last_msg.timestamp if last_msg else chat.created_at,
            "unread_count": db.query(Message).filter(and_(Message.chat_id == chat.id, Message.is_read == False, Message.sender_id != current_user.id)).count()
        })
    return sorted(results, key=lambda x: x['last_time'], reverse=True)

# ---------------- FILE UPLOAD ----------------
@app.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    ext = file.filename.split(".")[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    path = os.path.join(UPLOAD_DIR, filename)
    with open(path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"url": f"/uploads/{filename}"}

# ---------------- WEBSOCKET ----------------
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            await websocket.close()
            return
        await manager.connect(user.id, websocket)
        user.is_online = True
        db.commit()
        while True:
            data = await websocket.receive_json()
            if data['type'] == 'msg':
                msg = Message(
                    chat_id=data['chat_id'],
                    sender_id=user.id,
                    content=data['content'],
                    msg_type=data.get('msg_type', 'text')
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)
                await manager.broadcast_to_chat(db, msg.chat_id, {
                    "type": "new_message",
                    "id": msg.id,
                    "chat_id": msg.chat_id,
                    "sender_id": msg.sender_id,
                    "content": msg.content,
                    "msg_type": msg.msg_type,
                    "timestamp": msg.timestamp.isoformat()
                })
            elif data['type'] == 'typing':
                await manager.broadcast_to_chat(db, data['chat_id'], {
                    "type": "typing",
                    "chat_id": data['chat_id'],
                    "user_id": user.id,
                    "username": user.username
                })
    except WebSocketDisconnect:
        manager.disconnect(user.id, websocket)
        user.is_online = False
        user.last_seen = datetime.utcnow()
        db.commit()
    except Exception as e:
        logging.error(f"WebSocket error: {e}")
        await websocket.close()

# ---------------- MAIN ----------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
