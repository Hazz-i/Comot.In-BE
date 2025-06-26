from fastapi import FastAPI, Depends, HTTPException, Header,Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
import os
import dotenv

import requests

# Import dari modules lokal
from utils.database import SessionLocal, engine
from model.models import Base, User, BlacklistedToken, DownloadHistory
from helper.auth import (
    hash_password, 
    verify_password, 
    create_access_token, 
    decode_token,
    blacklist_token,
    decode_and_verify_token
)
from fastapi.responses import StreamingResponse, Response
from sqlalchemy import func


dotenv.load_dotenv()

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        os.getenv("URL", "http://localhost:5173"), 
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "https://comot-in.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    allow_origin_regex=r"http://localhost:\d+",  # Allow any localhost port
)

# Add explicit OPTIONS handler for all routes
@app.options("/{path:path}")
def options_handler(path: str):
    return {"message": "OK"}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterRequest(BaseModel):
    username: str
    email: str  # Ganti dari EmailStr ke str biasa
    password: str

class LoginRequest(BaseModel):
    login: str  # Bisa email atau username
    password: str

class DownloadHistoryResponse(BaseModel):
    id: int
    platform: str
    original_url: str
    downloaded_at: str
    
    class Config:
        from_attributes = True

class DownloadHistoryRequest(BaseModel):
    platform: str  # youtube, instagram, facebook
    original_url: str

@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    # Cek apakah username sudah ada
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Cek apakah email sudah ada
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Buat user baru dengan username, email, dan password
    user = User(
        username=req.username, 
        email=req.email, 
        password=hash_password(req.password)
    )
    db.add(user)
    db.commit()
    return {
        "message": "Successfully registered",
        "username": req.username,
        "email": req.email
    }

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    # Coba cari user berdasarkan email atau username
    user = db.query(User).filter(
        (User.email == req.login) | (User.username == req.login)
    ).first()
    
    if not user or not verify_password(req.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Gunakan username sebagai subject di JWT token
    token = create_access_token({"sub": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user.username,
        "email": user.email
    }

@app.post("/logout")
def logout(Authorization: str = Header(...), db: Session = Depends(get_db)):
    """
    Logout user dengan memvalidasi token dan menambahkannya ke blacklist
    """
    try:
        # Ambil token dari header Authorization
        token = Authorization.split(" ")[1]
        
        # Validasi token untuk memastikan token valid
        payload = decode_token(token)
        username = payload["sub"]
        
        # Tambahkan token ke blacklist
        if blacklist_token(token, db):
            return {
                "message": "Successfully logged out",
                "username": username,
                "action": "clear_token"  # Instruksi untuk frontend menghapus token
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to logout")
            
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/verify")
def verify_token(Authorization: str = Header(...), db: Session = Depends(get_db)):
    token = Authorization.split(" ")[1]
    payload = decode_and_verify_token(token, db)
    username = payload["sub"]
    
    # Ambil informasi user dari database
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "username": user.username,
        "email": user.email,
        "valid": True
    }

@app.get("/user/me")
def get_user_profile(Authorization: str = Header(...), db: Session = Depends(get_db)):
    """
    Mendapatkan detail profile user yang sedang login
    """
    try:
        # Ambil token dari header Authorization
        token = Authorization.split(" ")[1]
        
        # Validasi token dan cek blacklist
        payload = decode_and_verify_token(token, db)
        username = payload["sub"]
        
        # Ambil informasi lengkap user dari database
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "profile": {
                "display_name": user.username,  # Bisa ditambah field display_name nanti
                "member_since": user.created_at.strftime("%Y-%m-%d") if user.created_at else "Unknown",
                "account_type": "regular"  # Bisa ditambah role/type field nanti
            },
            "status": "active"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/user/{username}")
def get_user_by_username(username: str, db: Session = Depends(get_db)):
    """
    Mendapatkan informasi user berdasarkan username (public info)
    Tidak memerlukan authentication
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Return hanya informasi public
    return {
        "username": user.username,
        "profile": {
            "display_name": user.username,
            "member_since": user.created_at.strftime("%Y-%m-%d") if user.created_at else "Unknown",
        },
        "public": True
    }

@app.post("/download")
def proxy_download(
    Authorization: str = Header(default=None),
    platform: str = Query(..., enum=["youtube", "instagram", "facebook"]),
    url: str = Query(...),
    quality: int = Query(3),
    download: bool = Query(False),
    db: Session = Depends(get_db)
):
    token = None
    user = None
    if Authorization:
        try:
            token = Authorization.split(" ")[1]
            decoded = decode_and_verify_token(token, db)
            # Get user from decoded token
            user = db.query(User).filter(User.username == decoded["sub"]).first()
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token")

    node_url = f"{os.getenv('NODE_API_BASE')}/{platform}-download"
    params = {"url": url}
    if platform == "youtube":
        params["quality"] = str(quality)

    try:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        node_response = requests.get(node_url, params=params, headers=headers, stream=True)

        # Save download history if user is authenticated
        download_history = None
        if user:
            download_history = DownloadHistory(
                user_id=user.id,
                platform=platform,
                original_url=url
            )
            db.add(download_history)
            db.commit()

        if platform == "youtube":
            # Download sebagai buffer
            content = node_response.content
            headers_resp = {
                "Content-Disposition": f'attachment; filename="youtube_video.mp4"' if download else 'inline',
                "Accept-Ranges": "bytes",
                "Cache-Control": "no-cache"
            }

            content_length = node_response.headers.get("Content-Length")
            if content_length and content_length.isdigit():
                headers_resp["Content-Length"] = content_length

            return Response(
                content=content,
                media_type="video/mp4",
                headers=headers_resp
            )
        else:
            # Streaming response
            def stream_response_from_node():
                for chunk in node_response.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk

            headers_resp = {
                "Content-Disposition": f'attachment; filename="{platform}_video.mp4"' if download else 'inline',
                "Accept-Ranges": "bytes",
                "Cache-Control": "no-cache"
            }

            content_length = node_response.headers.get("Content-Length")
            if content_length and content_length.isdigit():
                headers_resp["Content-Length"] = content_length

            return StreamingResponse(
                stream_response_from_node(),
                media_type=node_response.headers.get("Content-Type", "video/mp4"),
                headers=headers_resp
            )
    except Exception as e:
        # If there's an error and download history was created, we could delete it
        if user and download_history:
            db.delete(download_history)
            db.commit()
        raise HTTPException(status_code=500, detail=f"Downloader error: {str(e)}")

# Download History Routes
@app.get("/download-history", response_model=list[DownloadHistoryResponse])
def get_download_history(
    Authorization: str = Header(...),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    platform: str = Query(None, enum=["youtube", "instagram", "facebook"]),
    db: Session = Depends(get_db)
):
    """Get download history for authenticated user"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        query = db.query(DownloadHistory).filter(DownloadHistory.user_id == user.id)
        
        if platform:
            query = query.filter(DownloadHistory.platform == platform)
        
        history = query.order_by(DownloadHistory.downloaded_at.desc()).offset(offset).limit(limit).all()
        
        # Format response
        response = []
        for item in history:
            response.append(DownloadHistoryResponse(
                id=item.id,
                platform=item.platform,
                original_url=item.original_url,
                downloaded_at=item.downloaded_at.strftime("%Y-%m-%d %H:%M:%S")
            ))
        
        return response
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/download-history/stats")
def get_download_stats(
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Get download statistics for authenticated user"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Total downloads
        total_downloads = db.query(DownloadHistory).filter(DownloadHistory.user_id == user.id).count()
        
        # Downloads by platform
        platform_stats = db.query(
            DownloadHistory.platform,
            func.count(DownloadHistory.id).label('count')
        ).filter(DownloadHistory.user_id == user.id).group_by(DownloadHistory.platform).all()
        
        return {
            "total_downloads": total_downloads,
            "platform_breakdown": [{"platform": p[0], "count": p[1]} for p in platform_stats],
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/download-history", response_model=DownloadHistoryResponse)
def add_download_history(
    request: DownloadHistoryRequest,
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Add download history entry for authenticated user"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate platform
        valid_platforms = ["youtube", "instagram", "facebook"]
        if request.platform not in valid_platforms:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid platform. Must be one of: {', '.join(valid_platforms)}"
            )
        
        # Validate URL format
        if not request.original_url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        
        # Create new download history entry
        download_history = DownloadHistory(
            user_id=user.id,
            platform=request.platform,
            original_url=request.original_url
        )
        
        db.add(download_history)
        db.commit()
        db.refresh(download_history)
        
        # Return the created entry
        return DownloadHistoryResponse(
            id=download_history.id,
            platform=download_history.platform,
            original_url=download_history.original_url,
            downloaded_at=download_history.downloaded_at.strftime("%Y-%m-%d %H:%M:%S")
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add download history: {str(e)}")