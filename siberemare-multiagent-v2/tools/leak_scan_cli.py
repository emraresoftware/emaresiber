#!/usr/bin/env python3
"""
SiberEmare API Leak Scanner CLI
================================
İnternet ortamında deşifre olmuş API anahtarlarını tarar ve raporlar.

Kullanım:
  python tools/leak_scan_cli.py scan example.com
  python tools/leak_scan_cli.py scan example.com --sources github,shodan
  python tools/leak_scan_cli.py scan example.com --local-dir /path/to/project
  python tools/leak_scan_cli.py local /path/to/project
"""

import asyncio
import sys
import os
import time
from datetime import datetime, timezone

# Proje kök dizinini Python path'e ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import click

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.live import Live
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


console = Console() if HAS_RICH else None


def print_banner():
    """ASCII banner göster."""
    banner = r"""
    ╔══════════════════════════════════════════════════════════════╗
    ║   ____  _ _               _____                             ║
    ║  / ___|(_) |__   ___ _ __| ____|_ __ ___   __ _ _ __ ___   ║
    ║  \___ \| | '_ \ / _ \ '__|  _| | '_ ` _ \ / _` | '__/ _ \  ║
    ║   ___) | | |_) |  __/ |  | |___| | | | | | (_| | | |  __/  ║
    ║  |____/|_|_.__/ \___|_|  |_____|_| |_| |_|\__,_|_|  \___|  ║
    ║                                                              ║
    ║           🔒 API LEAK SCANNER v1.0                          ║
    ║           Deşifre Olmuş API Anahtarı Tarayıcısı             ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    if HAS_RICH:
        console.print(banner, style="bold cyan")
    else:
        print(banner)


def show_config_status():
    """Mevcut API anahtarlarının durumunu göster."""
    keys = {
        "GITHUB_TOKEN": bool(os.getenv("GITHUB_TOKEN")),
        "SHODAN_API_KEY": bool(os.getenv("SHODAN_API_KEY")),
        "GOOGLE_API_KEY": bool(os.getenv("GOOGLE_API_KEY")),
        "GOOGLE_CX": bool(os.getenv("GOOGLE_CX")),
        "INTELX_API_KEY": bool(os.getenv("INTELX_API_KEY")),
    }

    if HAS_RICH:
        table = Table(title="🔑 API Anahtarı Durumu", box=box.ROUNDED)
        table.add_column("Servis", style="cyan")
        table.add_column("Durum", justify="center")
        table.add_column("Kaynak", style="dim")

        sources_map = {
            "GITHUB_TOKEN": ("GitHub Code Search", "github"),
            "SHODAN_API_KEY": ("Shodan", "shodan"),
            "GOOGLE_API_KEY": ("Google Custom Search", "google_dorks"),
            "GOOGLE_CX": ("Google Search Engine ID", "google_dorks"),
            "INTELX_API_KEY": ("Intelligence X", "intelx"),
        }
        for key, configured in keys.items():
            service, source = sources_map.get(key, (key, "?"))
            status = "✅ Aktif" if configured else "❌ Yok"
            table.add_row(service, status, source)

        # Ücretsiz kaynaklar
        table.add_row("URLScan.io", "✅ Aktif (Ücretsiz)", "urlscan")
        table.add_row("Paste Siteleri", "✅ Aktif (Ücretsiz)", "paste")
        console.print(table)
        console.print()
    else:
        print("\n🔑 API Anahtarı Durumu:")
        for key, configured in keys.items():
            status = "✅" if configured else "❌"
            print(f"  {status} {key}")
        print()


@click.group()
def cli():
    """SiberEmare API Leak Scanner — İnternet'te deşifre olmuş API anahtarlarını tarar."""
    pass


@cli.command("scan")
@click.argument("target")
@click.option(
    "--sources",
    default="github,shodan,google_dorks,urlscan,paste,intelx",
    help="Taranacak kaynaklar (virgülle ayırın)",
)
@click.option("--local-dir", default=None, help="Ayrıca yerel proje dizinini de tara")
@click.option("--output-dir", default="reports", help="Rapor çıktı dizini")
@click.option("--json-only", is_flag=True, help="Sadece JSON rapor üret")
@click.option("--no-ai", is_flag=True, help="AI özetleme kullanma")
def scan_command(target: str, sources: str, local_dir: str, output_dir: str,
                 json_only: bool, no_ai: bool):
    """Hedef domain/organizasyonu internet üzerinde tara.

    \b
    Örnekler:
      python tools/leak_scan_cli.py scan example.com
      python tools/leak_scan_cli.py scan myorg --sources github,shodan
      python tools/leak_scan_cli.py scan example.com --local-dir ./project
    """
    print_banner()
    show_config_status()

    source_list = [s.strip() for s in sources.split(",") if s.strip()]

    if HAS_RICH:
        console.print(Panel(
            f"[bold]Hedef:[/bold] {target}\n"
            f"[bold]Kaynaklar:[/bold] {', '.join(source_list)}\n"
            f"[bold]Yerel Tarama:[/bold] {local_dir or 'Hayır'}\n"
            f"[bold]Çıktı Dizini:[/bold] {output_dir}",
            title="📋 Tarama Ayarları",
            border_style="cyan",
        ))
        console.print()

    async def run_scan():
        from tools.api_leak_scanner import APILeakScanner, scan_local_files
        from tools.leak_report_generator import (
            generate_markdown_report,
            generate_json_report,
            generate_html_report,
        )

        start_time = time.time()

        # Internet taraması
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("🌐 Internet taraması yapılıyor...", total=None)
                scanner = APILeakScanner(target=target, sources=source_list)
                result = await scanner.run()
                progress.update(task, completed=True, description="✅ Internet taraması tamamlandı")
        else:
            print("🌐 Internet taraması yapılıyor...")
            scanner = APILeakScanner(target=target, sources=source_list)
            result = await scanner.run()
            print("✅ Internet taraması tamamlandı")

        # Yerel tarama (opsiyonel)
        if local_dir:
            if HAS_RICH:
                console.print("📁 Yerel dosya taraması yapılıyor...", style="yellow")
            else:
                print("📁 Yerel dosya taraması yapılıyor...")

            local_findings = scan_local_files(local_dir)
            result.credentials.extend(local_findings)
            result.total_findings += len(local_findings)
            result.critical_count += sum(1 for f in local_findings if f.severity == "CRITICAL")
            result.high_count += sum(1 for f in local_findings if f.severity == "HIGH")
            result.medium_count += sum(1 for f in local_findings if f.severity == "MEDIUM")
            result.low_count += sum(1 for f in local_findings if f.severity == "LOW")

            if local_findings:
                if HAS_RICH:
                    console.print(f"  📍 Yerel: {len(local_findings)} bulgu", style="red")
                else:
                    print(f"  📍 Yerel: {len(local_findings)} bulgu")

        elapsed = time.time() - start_time

        # ---- Sonuç Gösterimi ----
        if HAS_RICH:
            console.print()

            # Özet tablo
            summary_table = Table(title="📊 Tarama Sonuçları", box=box.DOUBLE_EDGE)
            summary_table.add_column("Metrik", style="bold")
            summary_table.add_column("Değer", justify="right")

            summary_table.add_row("Hedef", target)
            summary_table.add_row("Tarama Süresi", f"{elapsed:.1f}s")
            summary_table.add_row("Taranan Kaynaklar", str(len(result.sources_scanned)))
            summary_table.add_row("Toplam Bulgu", f"[bold]{result.total_findings}[/bold]")
            summary_table.add_row("🔴 Critical", f"[bold red]{result.critical_count}[/bold red]")
            summary_table.add_row("🟠 High", f"[bold #fd7e14]{result.high_count}[/bold #fd7e14]")
            summary_table.add_row("🟡 Medium", f"[bold yellow]{result.medium_count}[/bold yellow]")
            summary_table.add_row("🟢 Low", f"[bold green]{result.low_count}[/bold green]")

            console.print(summary_table)
            console.print()

            # Detaylı bulgu tablosu (ilk 30)
            if result.credentials:
                detail_table = Table(title="🔍 Detaylı Bulgular (Top 30)", box=box.SIMPLE_HEAVY)
                detail_table.add_column("#", style="dim", width=4)
                detail_table.add_column("Severity", width=10)
                detail_table.add_column("Tip", width=30)
                detail_table.add_column("Değer (Maskeli)", width=35)
                detail_table.add_column("Kaynak", width=12)
                detail_table.add_column("URL", width=40, no_wrap=True)

                sev_styles = {
                    "CRITICAL": "bold red",
                    "HIGH": "bold #fd7e14",
                    "MEDIUM": "bold yellow",
                    "LOW": "bold green",
                }

                sorted_creds = sorted(result.credentials, key=lambda c: {
                    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3
                }.get(c.severity, 4))

                for i, cred in enumerate(sorted_creds[:30], 1):
                    style = sev_styles.get(cred.severity, "")
                    detail_table.add_row(
                        str(i),
                        f"[{style}]{cred.severity}[/{style}]",
                        cred.credential_type,
                        cred.matched_value[:35],
                        cred.source,
                        cred.source_url[:40],
                    )

                console.print(detail_table)
                console.print()

        else:
            print(f"\n📊 Tarama Sonuçları:")
            print(f"  Hedef: {target}")
            print(f"  Süre: {elapsed:.1f}s")
            print(f"  Toplam: {result.total_findings}")
            print(f"  🔴 Critical: {result.critical_count}")
            print(f"  🟠 High: {result.high_count}")
            print(f"  🟡 Medium: {result.medium_count}")
            print(f"  🟢 Low: {result.low_count}")

        # ---- Rapor Üretimi ----
        if HAS_RICH:
            console.print("📝 Raporlar üretiliyor...", style="cyan")
        else:
            print("📝 Raporlar üretiliyor...")

        json_path = generate_json_report(result, output_dir)

        if not json_only:
            md_path = generate_markdown_report(result, output_dir)
            html_path = generate_html_report(result, output_dir)

            if HAS_RICH:
                report_table = Table(title="📄 Üretilen Raporlar", box=box.ROUNDED)
                report_table.add_column("Format", style="bold")
                report_table.add_column("Dosya Yolu")

                report_table.add_row("📋 Markdown", md_path)
                report_table.add_row("📊 JSON", json_path)
                report_table.add_row("🌐 HTML", html_path)
                console.print(report_table)
            else:
                print(f"  📋 Markdown: {md_path}")
                print(f"  📊 JSON: {json_path}")
                print(f"  🌐 HTML: {html_path}")
        else:
            if HAS_RICH:
                console.print(f"  📊 JSON: {json_path}")
            else:
                print(f"  📊 JSON: {json_path}")

        # Hatalar
        if result.errors:
            if HAS_RICH:
                console.print("\n⚠️  Tarama Hataları:", style="yellow")
                for err in result.errors:
                    console.print(f"  • {err}", style="dim red")
            else:
                print("\n⚠️  Tarama Hataları:")
                for err in result.errors:
                    print(f"  • {err}")

        # Final
        if HAS_RICH:
            if result.critical_count > 0:
                console.print(Panel(
                    f"[bold red]⚠️  {result.critical_count} KRİTİK SEVİYE SIZINTI TESPİT EDİLDİ![/bold red]\n\n"
                    "İlgili API anahtarları DERHAL iptal edilmeli (revoke) ve yeniden oluşturulmalıdır.\n"
                    "Yetkisiz erişim loglarını kontrol edin.",
                    title="🚨 ACİL AKSIYON GEREKLİ",
                    border_style="red",
                ))
            elif result.total_findings == 0:
                console.print(Panel(
                    "[bold green]✅ Sızıntı tespit edilmedi![/bold green]\n"
                    "Hedef için bilinen kaynaklarda deşifre olmuş API anahtarı bulunamadı.",
                    title="Temiz Sonuç",
                    border_style="green",
                ))
            else:
                console.print(Panel(
                    f"[bold yellow]Toplam {result.total_findings} potansiyel sızıntı tespit edildi.[/bold yellow]\n"
                    "Detaylar için oluşturulan raporları inceleyin.",
                    title="Tarama Tamamlandı",
                    border_style="yellow",
                ))

        return result

    asyncio.run(run_scan())


@cli.command("local")
@click.argument("directory")
@click.option("--output-dir", default="reports", help="Rapor çıktı dizini")
def local_command(directory: str, output_dir: str):
    """Yerel bir proje dizinindeki hardcoded credential'ları tara.

    \b
    Örnekler:
      python tools/leak_scan_cli.py local ./my-project
      python tools/leak_scan_cli.py local /path/to/repo --output-dir ./output
    """
    print_banner()

    from tools.api_leak_scanner import scan_local_files, ScanResult
    from tools.leak_report_generator import (
        generate_markdown_report,
        generate_json_report,
        generate_html_report,
    )

    if not os.path.isdir(directory):
        click.echo(f"❌ Dizin bulunamadı: {directory}")
        sys.exit(1)

    if HAS_RICH:
        console.print(f"📁 Yerel tarama: [bold]{directory}[/bold]")
        console.print()

    start_time = time.time()
    findings = scan_local_files(directory)
    elapsed = time.time() - start_time

    # ScanResult oluştur
    scan_id = f"LOCAL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    result = ScanResult(
        scan_id=scan_id,
        target=f"local:{directory}",
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity == "CRITICAL"),
        high_count=sum(1 for f in findings if f.severity == "HIGH"),
        medium_count=sum(1 for f in findings if f.severity == "MEDIUM"),
        low_count=sum(1 for f in findings if f.severity == "LOW"),
        sources_scanned=["local_file"],
        credentials=findings,
    )

    # Sonuçları göster
    if HAS_RICH:
        table = Table(title=f"📊 Yerel Tarama Sonuçları ({elapsed:.1f}s)", box=box.DOUBLE_EDGE)
        table.add_column("Metrik", style="bold")
        table.add_column("Değer", justify="right")
        table.add_row("Dizin", directory)
        table.add_row("Toplam Bulgu", f"[bold]{result.total_findings}[/bold]")
        table.add_row("🔴 Critical", f"[bold red]{result.critical_count}[/bold red]")
        table.add_row("🟠 High", f"[bold #fd7e14]{result.high_count}[/bold #fd7e14]")
        table.add_row("🟡 Medium", f"[bold yellow]{result.medium_count}[/bold yellow]")
        table.add_row("🟢 Low", f"[bold green]{result.low_count}[/bold green]")
        console.print(table)
    else:
        print(f"\n📊 Sonuçlar ({elapsed:.1f}s):")
        print(f"  Toplam: {result.total_findings}")
        print(f"  🔴 Critical: {result.critical_count}")
        print(f"  🟠 High: {result.high_count}")

    # Raporlar
    md_path = generate_markdown_report(result, output_dir)
    json_path = generate_json_report(result, output_dir)
    html_path = generate_html_report(result, output_dir)

    if HAS_RICH:
        console.print(f"\n📋 Markdown: {md_path}")
        console.print(f"📊 JSON: {json_path}")
        console.print(f"🌐 HTML: {html_path}")
    else:
        print(f"\n📋 {md_path}")
        print(f"📊 {json_path}")
        print(f"🌐 {html_path}")


@cli.command("check-env")
def check_env():
    """API anahtarlarının yapılandırma durumunu kontrol et."""
    print_banner()
    show_config_status()

    if HAS_RICH:
        console.print(Panel(
            "[bold]API anahtarlarınızı .env dosyasına ekleyin:[/bold]\n\n"
            "GITHUB_TOKEN=ghp_xxxxxxxxxxxx\n"
            "SHODAN_API_KEY=xxxxxxxxxxxxxxxx\n"
            "GOOGLE_API_KEY=AIzaxxxxxxxxxxxxxxxx\n"
            "GOOGLE_CX=xxxxxxxxxxxxxxx\n"
            "INTELX_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\n\n"
            "[dim]Not: URLScan.io ve Paste siteleri ücretsizdir, API anahtarı gerekmez.\n"
            "Anahtarı olmayan kaynaklar otomatik olarak atlanır.[/dim]",
            title="💡 Yapılandırma",
            border_style="blue",
        ))


@cli.command("patterns")
def show_patterns():
    """Desteklenen API key pattern'lerini listele."""
    print_banner()

    from tools.api_leak_scanner import API_KEY_PATTERNS, LOW_CONFIDENCE_PATTERNS, classify_severity

    if HAS_RICH:
        table = Table(title="🔑 Desteklenen API Key Pattern'leri", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Credential Tipi", style="bold", width=35)
        table.add_column("Severity", width=12)
        table.add_column("Güvenilirlik", width=12)
        table.add_column("Regex (kısaltılmış)", width=50, no_wrap=True)

        sev_styles = {
            "CRITICAL": "bold red",
            "HIGH": "bold #fd7e14",
            "MEDIUM": "bold yellow",
            "LOW": "bold green",
        }

        for i, (name, pattern) in enumerate(API_KEY_PATTERNS.items(), 1):
            sev = classify_severity(name)
            style = sev_styles.get(sev, "")
            conf = "LOW" if name in LOW_CONFIDENCE_PATTERNS else "HIGH"
            regex_str = pattern.pattern[:50] + ("..." if len(pattern.pattern) > 50 else "")
            table.add_row(
                str(i),
                name,
                f"[{style}]{sev}[/{style}]",
                conf,
                regex_str,
            )

        console.print(table)
        console.print(f"\nToplam: [bold]{len(API_KEY_PATTERNS)}[/bold] pattern")
    else:
        print(f"\nDesteklenen pattern sayısı: {len(API_KEY_PATTERNS)}")
        for name in API_KEY_PATTERNS:
            print(f"  • {name}")


if __name__ == "__main__":
    cli()
