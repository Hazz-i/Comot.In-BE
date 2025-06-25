# FastAPI Backend - Comot.in

Backend API untuk aplikasi Comot.in menggunakan FastAPI, SQLAlchemy, dan PostgreSQL.

## Struktur Proyek

```
comot.in-be/
├── helper/                 # Modul helper functions
│   ├── __init__.py
│   ├── auth.py            # Fungsi autentikasi (JWT, password hashing)
│   └── downloader_proxy.py # Proxy untuk downloader service
├── model/                 # Database models
│   ├── __init__.py
│   └── models.py          # SQLAlchemy models
├── utils/                 # Utilities
│   ├── __init__.py
│   └── database.py        # Database configuration
├── server.py              # Main FastAPI application
├── main.py               # Entry point untuk development
├── create_tables.py      # Script untuk membuat database tables
├── requirements.txt      # Python dependencies
├── .env.example         # Template environment variables
└── README.md           # Dokumentasi ini
```

## Setup dan Instalasi

### 1. Clone Repository dan Setup Virtual Environment

```bash
cd comot.in-be
python -m venv .venv
.venv\Scripts\activate  # Windows
# atau
source .venv/bin/activate  # Linux/Mac
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup Environment Variables

Copy file `.env.example` ke `.env` dan sesuaikan konfigurasi:

```bash
cp .env.example .env
```

Edit file `.env` dengan konfigurasi yang sesuai:

```env
# Database Configuration
POSTGRES_USER=your_username
POSTGRES_PASSWORD=your_password
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=your_database

# CORS Configuration
URL=http://localhost:5173

# JWT Secret Key
JWT_SECRET_KEY=your_very_secret_jwt_key_here
JWT_ALGORITHM=HS256
JWT_EXPIRE_HOURS=24
```

### 4. Setup Database

Pastikan PostgreSQL sudah running, lalu buat database tables:

```bash
python create_tables.py
```

### 5. Run Application

#### Development Mode:

```bash
python main.py
```

#### Atau menggunakan uvicorn langsung:

```bash
uvicorn server:app --reload --host 0.0.0.0 --port 8000
```

API akan tersedia di: `http://localhost:8000`

## API Endpoints

### Authentication

- `POST /register` - Registrasi user baru
- `POST /login` - Login user
- `GET /verify` - Verifikasi JWT token

### Download Service

- `POST /download` - Proxy request ke Node.js downloader

## Modules

### helper/auth.py

Menangani autentikasi dan autorization:

- `hash_password()` - Hash password menggunakan bcrypt
- `verify_password()` - Verifikasi password
- `create_access_token()` - Membuat JWT token
- `decode_token()` - Decode dan validasi JWT token

### helper/downloader_proxy.py

Proxy untuk komunikasi dengan Node.js downloader service.

### model/models.py

Database models menggunakan SQLAlchemy:

- `User` - Model untuk tabel users

### utils/database.py

Konfigurasi database dan SQLAlchemy setup.

## Development

### Menambah Model Baru

1. Tambahkan model di `model/models.py`
2. Update `model/__init__.py` untuk export model
3. Jalankan `python create_tables.py` untuk membuat tabel

### Menambah Endpoint Baru

1. Tambahkan endpoint di `server.py`
2. Import fungsi helper yang diperlukan dari modules

### Testing

Untuk testing API, gunakan:

- FastAPI automatic docs: `http://localhost:8000/docs`
- Postman atau tools serupa
- Frontend application di `http://localhost:5173`
