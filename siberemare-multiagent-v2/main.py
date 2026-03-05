"""SiberEmare Multi-Agent Orchestrator — Ana Giriş Noktası"""
import asyncio
import sys

from state import PentestState


async def run(request_id: str):
    from graph import async_app_with_sqlite

    state = PentestState(
        request_id=request_id,
        scope={"target": "app.example.com", "level": "L3"},
        raw_input="IDOR bulgusu PoC ile geldi",
    )
    thread = {"configurable": {"thread_id": request_id}}
    print(f"🚀 SiberEmare Multi-Agent başlatıldı — Request: {request_id}")

    async with async_app_with_sqlite() as production_app:
        async for event in production_app.astream(
            state.model_dump(), thread, stream_mode="values"
        ):
            stage = event.get("current_stage", "?")
            score = event.get("review_score", 0.0)
            iterations = event.get("self_critique_iterations", 0)
            print(f"[{stage}] Score: {score:.2f} | Self-Critique Tur: {iterations}")

    print(f"✅ Pipeline tamamlandı. Rapor: reports/{request_id}.md")


def main():
    request_id = sys.argv[1] if len(sys.argv) > 1 else "REQ-2026-TEST01"
    asyncio.run(run(request_id))


if __name__ == "__main__":
    main()
