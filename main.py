"""
Main entry point untuk aplikasi FastAPI
"""

if __name__ == "__main__":
    import uvicorn
    from server import app
    
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
