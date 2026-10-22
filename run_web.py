#!/usr/bin/env python3
"""Startet den antbb-Webserver."""
import os
import uvicorn

if __name__ == "__main__":
    host = os.environ.get("ANTBB_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("ANTBB_WEB_PORT", "8000"))
    uvicorn.run("antbb.web.app:app", host=host, port=port, reload=False)
