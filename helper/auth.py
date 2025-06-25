from fastapi import HTTPException
from jose import jwt, JWTError
from passlib.hash import bcrypt
import datetime
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_secret_key_please_change_this")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

def hash_password(password: str):
    return bcrypt.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=EXPIRE_HOURS)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def blacklist_token(token: str, db):
    """
    Menambahkan token ke blacklist
    """
    from model.models import BlacklistedToken
    
    try:
        # Decode token untuk mendapatkan expiry time
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        expires_at = datetime.datetime.fromtimestamp(payload['exp'])
        
        # Simpan ke blacklist
        blacklisted_token = BlacklistedToken(
            token=token,
            expires_at=expires_at
        )
        db.add(blacklisted_token)
        db.commit()
        return True
    except Exception as e:
        db.rollback()
        return False

def is_token_blacklisted(token: str, db):
    """
    Mengecek apakah token sudah di-blacklist
    """
    from model.models import BlacklistedToken
    
    blacklisted = db.query(BlacklistedToken).filter(BlacklistedToken.token == token).first()
    return blacklisted is not None

def decode_and_verify_token(token: str, db=None):
    """
    Decode token dan verifikasi apakah tidak di-blacklist
    """
    try:
        # Decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Jika database session tersedia, cek blacklist
        if db and is_token_blacklisted(token, db):
            raise HTTPException(status_code=401, detail="Token has been blacklisted")
        
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
