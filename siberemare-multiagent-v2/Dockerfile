FROM python:3.11-slim

WORKDIR /app

# Sistem bağımlılıkları
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python bağımlılıkları
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Uygulama dosyaları
COPY . .

# Reports dizini
RUN mkdir -p reports

EXPOSE 8080

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

CMD ["python", "web/app.py"]
