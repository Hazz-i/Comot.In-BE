import requests
from fastapi import HTTPException

NODE_DOWNLOADER_URL = "http://localhost:3001/download"

def call_node_downloader(token: str):
    try:
        res = requests.post(NODE_DOWNLOADER_URL, headers={
            "Authorization": f"Bearer {token}"
        })
        if res.status_code != 200:
            raise HTTPException(status_code=502, detail="Downloader failed")
        return res.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error contacting downloader")
