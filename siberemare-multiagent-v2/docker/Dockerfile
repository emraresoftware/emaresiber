FROM python:3.12-slim

WORKDIR /app

# System dependencies (tesseract for OCR)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    tesseract-ocr-tur \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Volumes for persistence
VOLUME ["/app/checkpoints", "/app/reports", "/app/knowledge_base"]

EXPOSE 8000

CMD ["python", "main.py", "REQ-2026-TEST01"]
