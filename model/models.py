from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from utils.database import Base
import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String) 
    role = Column(String, default="user")  # user, admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationship dengan DownloadHistory
    download_history = relationship("DownloadHistory", back_populates="user")
    reviews = relationship("Reviews", back_populates="user")

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True)
    blacklisted_on = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime)  # Untuk cleanup otomatis token yang sudah expired

class DownloadHistory(Base):
    __tablename__ = "download_history"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    platform = Column(String, nullable=False)  # youtube, instagram, facebook
    original_url = Column(Text, nullable=False)  # URL asli yang di-download
    downloaded_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationship dengan User
    user = relationship("User", back_populates="download_history")

class Reviews(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    score = Column(Integer, nullable=False)  # Rating score (e.g., 1-5 stars)
    message = Column(Text, nullable=False)  # Review message/comment
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationship dengan User
    user = relationship("User", back_populates="reviews")
