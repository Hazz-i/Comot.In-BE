from fastapi import FastAPI, Depends, HTTPException, Header,Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pydantic import BaseModel
import os
import dotenv

import requests
import datetime

# Import dari modules lokal
from utils.database import SessionLocal, engine
from model.models import Base, User, BlacklistedToken, DownloadHistory, Reviews
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

class ReviewRequest(BaseModel):
    score: int  # 1-5 stars
    message: str

class ReviewResponse(BaseModel):
    id: int
    score: int
    message: str
    created_at: str
    username: str
    
    class Config:
        from_attributes = True

class AdminRegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    admin_secret: str

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
        "email": user.email,
        "role": user.role
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
            "role": user.role,
            "profile": {
                "member_since": user.created_at.strftime("%Y-%m-%d") if user.created_at else "Unknown",
                "account_type": user.role  # Use actual role instead of hardcoded "regular"
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
    # Initialize variables
    user = None
    token = None
    
    # Only try to authenticate if Authorization header is provided
    if Authorization:
        try:
            token = Authorization.split(" ")[1]
            decoded = decode_and_verify_token(token, db)
            # Get user from decoded token
            user = db.query(User).filter(User.username == decoded["sub"]).first()
        except Exception:
            # If token is invalid, continue without authentication
            user = None
            token = None

    node_url = f"{os.getenv('NODE_API_BASE')}/{platform}-download"
    params = {"url": url}
    if platform == "youtube":
        params["quality"] = str(quality)

    try:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        node_response = requests.get(node_url, params=params, headers=headers, stream=True)

        # Save download history ONLY if user is authenticated
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
        # If there's an error and download history was created, delete it
        if user and download_history:
            try:
                db.delete(download_history)
                db.commit()
            except:
                pass  # Ignore rollback errors
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

@app.delete("/download-history/{history_id}")
def delete_download_history(
    history_id: int,
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Delete a download history entry"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the download history entry
        history_entry = db.query(DownloadHistory).filter(
            DownloadHistory.id == history_id,
            DownloadHistory.user_id == user.id
        ).first()
        
        if not history_entry:
            raise HTTPException(status_code=404, detail="Download history not found")
        
        db.delete(history_entry)
        db.commit()
        
        return {"message": "Download history deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete download history: {str(e)}")

# Reviews Routes
@app.post("/reviews", response_model=ReviewResponse)
def add_review(
    request: ReviewRequest,
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Add a new review"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate score range
        if not (1 <= request.score <= 5):
            raise HTTPException(status_code=400, detail="Score must be between 1 and 5")
        
        # Validate message length
        if len(request.message.strip()) < 10:
            raise HTTPException(status_code=400, detail="Review message must be at least 10 characters")
        
        # Check if user already has a review (optional: limit one review per user)
        existing_review = db.query(Reviews).filter(Reviews.user_id == user.id).first()
        if existing_review:
            raise HTTPException(status_code=400, detail="You have already submitted a review. Use PUT to update it.")
        
        # Create new review
        review = Reviews(
            user_id=user.id,
            score=request.score,
            message=request.message.strip()
        )
        
        db.add(review)
        db.commit()
        db.refresh(review)
        
        return ReviewResponse(
            id=review.id,
            score=review.score,
            message=review.message,
            created_at=review.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            username=user.username
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add review: {str(e)}")

@app.get("/reviews", response_model=list[ReviewResponse])
def get_reviews(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    score_filter: int = Query(None, ge=1, le=5),
    db: Session = Depends(get_db)
):
    """Get all reviews (public endpoint)"""
    try:
        query = db.query(Reviews, User).join(User, Reviews.user_id == User.id)
        
        if score_filter:
            query = query.filter(Reviews.score == score_filter)
        
        reviews = query.order_by(Reviews.created_at.desc()).offset(offset).limit(limit).all()
        
        response = []
        for review, user in reviews:
            response.append(ReviewResponse(
                id=review.id,
                score=review.score,
                message=review.message,
                created_at=review.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                username=user.username
            ))
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch reviews: {str(e)}")

@app.get("/reviews/stats")
def get_review_stats(db: Session = Depends(get_db)):
    """Get review statistics (public endpoint)"""
    try:
        total_reviews = db.query(Reviews).count()
        
        if total_reviews == 0:
            return {
                "total_reviews": 0,
                "average_score": 0,
                "score_breakdown": {str(i): 0 for i in range(1, 6)}
            }
        
        # Average score
        avg_score = db.query(func.avg(Reviews.score)).scalar() or 0
        
        # Score breakdown
        score_breakdown = {}
        for i in range(1, 6):
            count = db.query(Reviews).filter(Reviews.score == i).count()
            score_breakdown[str(i)] = count
        
        return {
            "total_reviews": total_reviews,
            "average_score": round(float(avg_score), 2),
            "score_breakdown": score_breakdown
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch review stats: {str(e)}")

@app.get("/reviews/me", response_model=list[ReviewResponse])
def get_my_reviews(
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Get reviews by the authenticated user"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        reviews = db.query(Reviews).filter(Reviews.user_id == user.id).order_by(Reviews.created_at.desc()).all()
        
        response = []
        for review in reviews:
            response.append(ReviewResponse(
                id=review.id,
                score=review.score,
                message=review.message,
                created_at=review.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                username=user.username
            ))
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch your reviews: {str(e)}")

@app.put("/reviews/{review_id}", response_model=ReviewResponse)
def update_review(
    review_id: int,
    request: ReviewRequest,
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Update user's own review"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the review
        review = db.query(Reviews).filter(
            Reviews.id == review_id,
            Reviews.user_id == user.id
        ).first()
        
        if not review:
            raise HTTPException(status_code=404, detail="Review not found or not owned by you")
        
        # Validate score and message
        if not (1 <= request.score <= 5):
            raise HTTPException(status_code=400, detail="Score must be between 1 and 5")
        
        if len(request.message.strip()) < 10:
            raise HTTPException(status_code=400, detail="Review message must be at least 10 characters")
        
        # Update review
        review.score = request.score
        review.message = request.message.strip()
        
        db.commit()
        db.refresh(review)
        
        return ReviewResponse(
            id=review.id,
            score=review.score,
            message=review.message,
            created_at=review.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            username=user.username
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update review: {str(e)}")

@app.delete("/reviews/{review_id}")
def delete_review(
    review_id: int,
    Authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """Delete user's own review"""
    try:
        token = Authorization.split(" ")[1]
        decoded = decode_and_verify_token(token, db)
        user = db.query(User).filter(User.username == decoded["sub"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Find the review
        review = db.query(Reviews).filter(
            Reviews.id == review_id,
            Reviews.user_id == user.id
        ).first()
        
        if not review:
            raise HTTPException(status_code=404, detail="Review not found or not owned by you")
        
        db.delete(review)
        db.commit()
        
        return {"message": "Review deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete review: {str(e)}")

# Admin Routes
@app.get("/admin/users")
def admin_get_users(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    role_filter: str = Query(None, enum=["user", "admin"]),
    db: Session = Depends(get_db)
):
    """Admin: Get all users"""
    try:
        query = db.query(User)
        
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        users = query.offset(offset).limit(limit).all()
        
        response = []
        for user in users:
            user_stats = {
                "download_count": db.query(DownloadHistory).filter(DownloadHistory.user_id == user.id).count(),
                "review_count": db.query(Reviews).filter(Reviews.user_id == user.id).count()
            }
            
            response.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S") if user.created_at else "Unknown",
                "stats": user_stats
            })
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch users: {str(e)}")

@app.get("/admin/stats")
def admin_get_stats(
    db: Session = Depends(get_db)
):
    """Admin: Get system statistics"""
    try:
        total_users = db.query(User).count()
        total_admins = db.query(User).filter(User.role == "admin").count()
        total_downloads = db.query(DownloadHistory).count()
        total_reviews = db.query(Reviews).count()
        
        # Downloads by platform
        platform_stats = db.query(
            DownloadHistory.platform,
            func.count(DownloadHistory.id).label('count')
        ).group_by(DownloadHistory.platform).all()
        
        # Reviews by score
        review_stats = db.query(
            Reviews.score,
            func.count(Reviews.id).label('count')
        ).group_by(Reviews.score).all()
        
        # Recent activity (last 7 days)
        from datetime import datetime, timedelta
        week_ago = datetime.utcnow() - timedelta(days=7)
        
        recent_users = db.query(User).filter(User.created_at >= week_ago).count()
        recent_downloads = db.query(DownloadHistory).filter(DownloadHistory.downloaded_at >= week_ago).count()
        recent_reviews = db.query(Reviews).filter(Reviews.created_at >= week_ago).count()
        
        return {
            "system": {
                "total_users": total_users,
                "total_admins": total_admins,
                "total_downloads": total_downloads,
                "total_reviews": total_reviews
            },
            "breakdowns": {
                "downloads_by_platform": [{"platform": p[0], "count": p[1]} for p in platform_stats],
                "reviews_by_score": [{"score": r[0], "count": r[1]} for r in review_stats]
            },
            "recent_activity": {
                "new_users_last_7_days": recent_users,
                "downloads_last_7_days": recent_downloads,
                "reviews_last_7_days": recent_reviews
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch admin stats: {str(e)}")

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.datetime.utcnow()}

@app.get("/")
def root():
    return {"message": "Comot.in API is running", "status": "ok"}

@app.get("/db-test")
def test_database_connection(db: Session = Depends(get_db)):
    try:
        # Test simple query
        db.execute("SELECT 1")
        return {"status": "connected", "database": "postgresql"}
    except Exception as e:
        return {"status": "disconnected", "error": str(e)}