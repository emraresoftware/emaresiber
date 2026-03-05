"""100 Senaryoluk Tam Benchmark + PDF Rapor

Kullanım:
    python -m tests.benchmark_100

Gereksinimler:
    tests/test_cases/*.json  (her dosya bir PentestState uyumlu JSON)
    pip install fpdf2
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from glob import glob

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state import PentestState
from graph import app


# ------------------------------------------------------------------ #
# Demo test seti (test_cases/ klasörü boşsa fallback)
# ------------------------------------------------------------------ #

DEMO_TEST_SET = [
    {
        "request_id": f"BENCH-{i:03d}",
        "scope": {"target": "app.example.com", "level": "L3"},
        "raw_input": f"Test {i}: IDOR/SQLi/XSS PoC senaryosu",
    }
    for i in range(1, 101)
]


async def run_100_benchmark():
    # JSON dosyalarını yükle (eksikse demo kullan)
    test_files = sorted(glob("tests/test_cases/*.json"))[:100]
    if test_files:
        test_set = []
        for fpath in test_files:
            with open(fpath, encoding="utf-8") as f:
                test_set.append(json.load(f))
    else:
        print("⚠️  test_cases/ klasörü boş — Demo test seti kullanılıyor")
        test_set = DEMO_TEST_SET

    results = []
    for i, data in enumerate(test_set, 1):
        try:
            state = PentestState(**data)
        except Exception as e:
            print(f"[{i}/{len(test_set)}] State parse hatası: {e}")
            continue

        final_score = 0.0
        iterations = 0
        try:
            async for event in app.astream(
                state.model_dump(),
                {"configurable": {"thread_id": state.request_id}},
                stream_mode="values",
            ):
                if "review_score" in event:
                    final_score = event.get("review_score", 0.0)
                    iterations = event.get("self_critique_iterations", 0)
        except Exception as e:
            print(f"  ⚠️  {state.request_id}: {e}")

        results.append(
            {
                "id": state.request_id,
                "iterations": iterations,
                "score": final_score,
                "pass": final_score >= 0.95,
            }
        )
        print(
            f"[{i}/{len(test_set)}] {state.request_id}: score={final_score:.3f} iterations={iterations} {'✓' if final_score >= 0.95 else '✗'}"
        )

    # ------------------------------------------------------------------ #
    # İstatistikler
    # ------------------------------------------------------------------ #
    n = len(results)
    if n == 0:
        print("Sonuç yok.")
        return

    pass_rate = sum(1 for r in results if r["pass"]) / n * 100
    avg_iter = sum(r["iterations"] for r in results) / n
    avg_score = sum(r["score"] for r in results) / n

    print(f"\n{'='*50}")
    print(f"TOPLAM: {n} senaryo")
    print(f"Pass Rate       : {pass_rate:.1f}%")
    print(f"Ortalama Tur    : {avg_iter:.2f}")
    print(f"Ortalama Skor   : {avg_score:.3f}")
    print(f"{'='*50}")

    # PDF raporu
    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "SiberEmare 100 Senaryo Benchmark Raporu", ln=1, align="C")
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=1)
        pdf.cell(
            0,
            8,
            f"Pass Rate: {pass_rate:.1f}% | Ort. Tur: {avg_iter:.2f} | Ort. Skor: {avg_score:.3f}",
            ln=1,
        )
        pdf.ln(5)
        # Tablo başlıkları
        for header, width in [("ID", 60), ("Tur", 30), ("Skor", 35), ("Geçti?", 25)]:
            pdf.cell(width, 8, header, 1)
        pdf.ln()
        for r in results:
            pdf.cell(60, 7, str(r["id"]), 1)
            pdf.cell(30, 7, str(r["iterations"]), 1)
            pdf.cell(35, 7, f"{r['score']:.3f}", 1)
            pdf.cell(25, 7, "OK" if r["pass"] else "FAIL", 1)
            pdf.ln()

        pdf.output("benchmark_100.pdf")
        print("✅ benchmark_100.pdf oluşturuldu")
    except ImportError:
        print("⚠️  fpdf2 yüklü değil — pip install fpdf2")


if __name__ == "__main__":
    asyncio.run(run_100_benchmark())
