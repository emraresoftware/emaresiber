#!/bin/bash
# Emare Siber — Başlatma Scripti

echo "🚀 Emare Siber başlatılıyor..."

# Sanal ortam aktif et
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Ana uygulamayı başlat
if [ -f "main.py" ]; then
    python3 main.py
elif [ -f "app.py" ]; then
    python3 app.py
elif [ -f "backend/main.py" ]; then
    cd backend && python3 main.py
else
    echo "❌ Başlatılacak dosya bulunamadı!"
fi
