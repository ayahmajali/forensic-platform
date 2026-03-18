#!/usr/bin/env python3
"""
Startup script for Digital Forensics Investigation Platform
Handles .env loading and server startup
"""

import os
import sys
from pathlib import Path

# Load .env if exists
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    with open(str(env_file)) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

# Print startup info
print("=" * 60)
print("  Digital Forensics Investigation Platform")
print("  Version 1.0.0")
print("=" * 60)
print(f"  Server: http://0.0.0.0:8000")
print(f"  OpenAI: {'✅ Configured' if os.getenv('OPENAI_API_KEY') else '⚠️  Not configured (template summaries)'}")

# Check TSK
import shutil
tools = ["mmls", "fsstat", "fls", "tsk_recover", "exiftool"]
for tool in tools:
    status = "✅" if shutil.which(tool) else "❌"
    print(f"  {tool}: {status}")
print("=" * 60)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=True,
        log_level="info"
    )
