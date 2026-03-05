"""PentestX CLI Wrapper — multiagent + leak-scan komutları"""
import asyncio
import click
import sys
import os
import time

# Proje kök dizinini Python path'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph import app
from state import PentestState


@click.group()
def cli():
    """SiberEmare PentestX CLI"""
    pass


@cli.command("multiagent")
@click.argument("request_id")
@click.option("--max-critique", default=3, show_default=True, help="Self-critique maks tur")
@click.option("--target", default="auto", help="Hedef domain / IP")
@click.option("--level", default="L3", help="PentestX kademe (L0-L6)")
@click.option("--raw-input", default="CLI başlatıldı", help="Ham bulgu metni")
def multiagent(request_id: str, max_critique: int, target: str, level: str, raw_input: str):
    """pentestx multiagent REQ-xxx --max-critique 2"""

    state = PentestState(
        request_id=request_id,
        scope={"target": target, "level": level},
        raw_input=raw_input,
        max_iterations=max_critique,
    )
    thread = {"configurable": {"thread_id": request_id}}

    async def run():
        async for event in app.astream(state.model_dump(), thread, stream_mode="values"):
            stage = event.get("current_stage", "?")
            score = event.get("review_score", 0.0)
            itr = event.get("self_critique_iterations", 0)
            click.echo(f"[{stage}] Score: {score:.2f} | Tur: {itr}")

    asyncio.run(run())
    click.echo(f"✅ Rapor hazır: reports/{request_id}.md")


@cli.command("leak-scan")
@click.argument("target")
@click.option("--sources", default="github,shodan,google_dorks,urlscan,paste,intelx",
              help="Taranacak kaynaklar (virgülle ayırın)")
@click.option("--local-dir", default=None, help="Yerel proje dizini de taransın")
@click.option("--output-dir", default="reports", help="Rapor çıktı dizini")
def leak_scan(target: str, sources: str, local_dir: str, output_dir: str):
    """İnternet'te deşifre olmuş API anahtarlarını tara.

    \b
    Örnekler:
      python tools/cli.py leak-scan example.com
      python tools/cli.py leak-scan myorg --sources github,shodan
    """
    from tools.api_leak_scanner import APILeakScanner, scan_local_files
    from tools.leak_report_generator import (
        generate_markdown_report,
        generate_json_report,
        generate_html_report,
    )

    source_list = [s.strip() for s in sources.split(",") if s.strip()]
    click.echo(f"🔒 SiberEmare API Leak Scanner")
    click.echo(f"   Hedef: {target}")
    click.echo(f"   Kaynaklar: {', '.join(source_list)}")
    click.echo()

    async def run():
        start = time.time()
        scanner = APILeakScanner(target=target, sources=source_list)
        result = await scanner.run()

        if local_dir:
            local = scan_local_files(local_dir)
            result.credentials.extend(local)
            result.total_findings += len(local)
            result.critical_count += sum(1 for f in local if f.severity == "CRITICAL")
            result.high_count += sum(1 for f in local if f.severity == "HIGH")
            result.medium_count += sum(1 for f in local if f.severity == "MEDIUM")
            result.low_count += sum(1 for f in local if f.severity == "LOW")

        elapsed = time.time() - start

        click.echo(f"📊 Sonuçlar ({elapsed:.1f}s):")
        click.echo(f"   Toplam: {result.total_findings}")
        click.echo(f"   🔴 Critical: {result.critical_count}")
        click.echo(f"   🟠 High: {result.high_count}")
        click.echo(f"   🟡 Medium: {result.medium_count}")
        click.echo(f"   🟢 Low: {result.low_count}")

        md = generate_markdown_report(result, output_dir)
        js = generate_json_report(result, output_dir)
        ht = generate_html_report(result, output_dir)

        click.echo(f"\n📋 Raporlar:")
        click.echo(f"   Markdown: {md}")
        click.echo(f"   JSON: {js}")
        click.echo(f"   HTML: {ht}")

        if result.critical_count > 0:
            click.echo(f"\n🚨 DİKKAT: {result.critical_count} KRİTİK sızıntı! Acil aksiyon gerekli.")

    asyncio.run(run())


if __name__ == "__main__":
    cli()
