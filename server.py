from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
import os
import dotenv

# Import dari modules lokal
from utils.database import SessionLocal, engine
from model.models import Base, User
from helper.auth import hash_password, verify_password, create_access_token, decode_token
from helper.downloader_proxy import call_node_downloader

dotenv.load_dotenv()

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("URL", "http://localhost:5173"), "http://127.0.0.1:5173"],  # Add your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="User already exists")
    user = User(username=req.username, email=req.email, password=hash_password(req.password))
    db.add(user)
    db.commit()
    return {"message": "Registered"}

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.email})
    return {"access_token": token}

@app.get("/verify")
def verify_token(Authorization: str = Header(...)):
    token = Authorization.split(" ")[1]
    payload = decode_token(token)
    return {"email": payload["sub"]}

@app.post("/download")
def proxy_download(Authorization: str = Header(None), db: Session = Depends(get_db)):
    if Authorization:
        token = Authorization.split(" ")[1]
        user_data = decode_token(token)
        # Anda bisa catat download per user di sini jika mau
        return call_node_downloader(token)
    else:
        # Logika pengguna guest: misalnya counter disimpan di cookie FE, atau IP tracked di DB
        raise HTTPException(status_code=403, detail="Guest access not allowed here")