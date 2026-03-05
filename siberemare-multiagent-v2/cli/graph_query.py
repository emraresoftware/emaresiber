"""Graph Query CLI — pentestx graph-query "IDOR zinciri L5 risk" --format html"""
import asyncio
import json
import os
import sys
import click

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_rag.optimized_graphrag import OptimizedGraphRAG


def generate_html_report(result: dict) -> str:
    query = result.get("query", "")
    chains = result.get("attack_chains", [])
    chain_rows = "\n".join(f"<tr><td>{c}</td></tr>" for c in chains)
    return f"""<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><title>SiberEmare Graph Query — {query}</title>
<style>body{{font-family:Segoe UI,sans-serif;padding:20px;background:#f5f5f5;}}
table{{border-collapse:collapse;width:100%;}}td,th{{border:1px solid #ccc;padding:8px;}}
h1{{color:#1e88e5;}}</style></head>
<body>
<h1>🔗 Graph Query: {query}</h1>
<p>Kademe: {result.get('level','?')} | Visualizer: <a href="{result.get('visualizer_link','#')}">Aç</a></p>
<h2>Saldırı Zincirleri</h2>
<table><tr><th>Zincir</th></tr>{chain_rows}</table>
<pre>{json.dumps(result.get('results',[]), indent=2, ensure_ascii=False)}</pre>
</body></html>"""


@click.command("graph-query")
@click.argument("query", nargs=-1, type=click.STRING)
@click.option("--level", default="L5", show_default=True, help="L3/L4/L5/L6 filtre")
@click.option(
    "--format",
    "fmt",
    default="text",
    type=click.Choice(["text", "json", "html"]),
    show_default=True,
)
def graph_query(query, level, fmt):
    """pentestx graph-query \"IDOR zinciri L5 risk\" --level L5 --format html"""
    q = " ".join(query)
    rag = OptimizedGraphRAG()
    result = asyncio.run(rag.hybrid_graph_query(q, level=level))

    if fmt == "json":
        click.echo(json.dumps(result, indent=2, ensure_ascii=False))
    elif fmt == "html":
        os.makedirs("frontend/visualizer/output", exist_ok=True)
        filename = f"frontend/visualizer/output/{q.replace(' ', '_')}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(generate_html_report(result))
        click.echo(f"✅ HTML raporu oluşturuldu: {filename}")
    else:
        chains = result.get("attack_chains", [])
        click.echo(f"🔗 Saldırı Zincirleri ({level}):")
        if chains:
            for c in chains:
                click.echo(f"  → {c}")
        else:
            click.echo("  Sonuç bulunamadı.")


if __name__ == "__main__":
    graph_query()
