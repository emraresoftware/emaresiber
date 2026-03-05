"""Mock LLM ile end-to-end pipeline akış testi"""
import asyncio
import os
import sys

# Proje kök dizinini Python yoluna ekle
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import AsyncMock, MagicMock, patch

os.environ['ANTHROPIC_API_KEY'] = 'test'
os.environ['OPENAI_API_KEY'] = 'test'

# Mock LLM yanıtı oluştur
mock_response = MagicMock()
mock_response.content = '{"compliance_status": true, "level": "L3", "data_level": "D1", "runbook": "L3_web.yaml", "approvals_required": 2, "red_flag": false}'


async def run_pipeline_test():
    with (
        patch('langchain_anthropic.ChatAnthropic.ainvoke', new=AsyncMock(return_value=mock_response)),
        patch('langchain_openai.ChatOpenAI.ainvoke', new=AsyncMock(return_value=mock_response)),
    ):
        from graph import app
        from state import PentestState

        state = PentestState(
            request_id='MOCK-TEST-001',
            scope={'target': 'app.example.com', 'level': 'L3'},
            raw_input='IDOR PoC test',
        )

        events = []
        async for event in app.astream(
            state.model_dump(),
            {'configurable': {'thread_id': 'MOCK-TEST-001'}},
            stream_mode='values',
        ):
            stage = event.get('current_stage', '?')
            events.append(stage)
            score = event.get('review_score', 0.0)
            itr = event.get('self_critique_iterations', 0)
            print(f'  → stage: {stage:<30} score: {score:.2f}  tur: {itr}')
            # Sonsuz döngü koruması
            if len(events) > 12:
                print('  [max event sınırı]')
                break

        return events


if __name__ == '__main__':
    print('=== SiberEmare Pipeline Akış Testi (Mock LLM) ===')
    events = asyncio.run(run_pipeline_test())
    print()
    print(f'✓ Pipeline testi tamamlandı — {len(events)} event işlendi')
