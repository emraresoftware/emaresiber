"""Self-Critique Döngüsü 50 Senaryo Benchmark + PDF Sonuç Raporu

Kullanım:
    python -m tests.benchmark_self_critique
"""

import asyncio
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from state import PentestState
from graph import app

TEST_SET = [
    {
        "request_id": f"BENCH-SC-{i:02d}",
        "scope": {"target": "app.example.com", "level": "L3"},
        "raw_input": f"Test {i}: IDOR/SQLi/XSS PoC screenshot ile",
        "max_iterations": 3,
    }
    for i in range(1, 51)
]


async def run_full_benchmark():
    results = []

    for i, test in enumerate(TEST_SET, 1):
        state = PentestState(**test)
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

        passed = final_score >= 0.95
        results.append(
            {
                "test_id": state.request_id,
                "iterations": iterations,
                "final_score": final_score,
                "passed": passed,
            }
        )
        print(
            f"[{i}/50] {state.request_id}: {final_score:.3f} ({iterations} tur) {'✓' if passed else '✗'}"
        )

    # ------------------------------------------------------------------ #
    # İstatistikler
    # ------------------------------------------------------------------ #
    avg_iterations = sum(r["iterations"] for r in results) / 50
    pass_rate = sum(1 for r in results if r["passed"]) / 50 * 100
    avg_score = sum(r["final_score"] for r in results) / 50

    print(f"\n{'='*50}")
    print(f"Pass Rate       : {pass_rate:.1f}%")
    print(f"Ortalama Tur    : {avg_iterations:.2f}")
    print(f"Ortalama Skor   : {avg_score:.3f}")
    print(f"{'='*50}")

    # PDF raporu
    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(
            0,
            10,
            "SiberEmare Self-Critique Benchmark Raporu — Mart 2026",
            ln=1,
            align="C",
        )
        pdf.set_font("Arial", "", 11)
        pdf.cell(0, 8, f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=1)
        pdf.cell(
            0,
            8,
            f"50 Senaryo | Pass: {pass_rate:.1f}% | Ort. Tur: {avg_iterations:.2f} | Ort. Skor: {avg_score:.3f}",
            ln=1,
        )
        pdf.ln(5)
        for header, width in [("Test ID", 60), ("Tur", 25), ("Skor", 35), ("Geçti?", 25)]:
            pdf.cell(width, 8, header, 1)
        pdf.ln()
        for r in results:
            pdf.cell(60, 7, str(r["test_id"]), 1)
            pdf.cell(25, 7, str(r["iterations"]), 1)
            pdf.cell(35, 7, f"{r['final_score']:.3f}", 1)
            pdf.cell(25, 7, "OK" if r["passed"] else "FAIL", 1)
            pdf.ln()
        pdf.output("benchmark_self_critique_50.pdf")
        print("✅ benchmark_self_critique_50.pdf oluşturuldu")
    except ImportError:
        print("⚠️  fpdf2 yüklü değil — pip install fpdf2")


if __name__ == "__main__":
    asyncio.run(run_full_benchmark())
