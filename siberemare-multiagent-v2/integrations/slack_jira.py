"""Slack + Jira entegrasyonu — Human-in-loop bildirimi + otomatik ticket oluşturma"""
import os
from state import PentestState


async def send_slack_approval(state: PentestState) -> None:
    """Human-in-loop: Slack kanalına onay butonu gönder."""
    token = os.getenv("SLACK_BOT_TOKEN", "")
    channel = os.getenv("SLACK_CHANNEL", "#pentest-approvals")

    if not token:
        print(
            f"[Slack] SLACK_BOT_TOKEN eksik — Human review: {state.request_id} | Stage: {state.current_stage}"
        )
        return

    try:
        from slack_sdk.web.async_client import AsyncWebClient

        client = AsyncWebClient(token=token)
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🛑 HUMAN REVIEW REQUIRED*\n"
                        f"Request: `{state.request_id}`\n"
                        f"Stage: {state.current_stage}\n"
                        f"Score: {state.review_score:.2f}\n"
                        f"Self-Critique Tur: {state.self_critique_iterations}"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Onayla"},
                        "style": "primary",
                        "value": state.request_id,
                        "action_id": "approve",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reddet"},
                        "style": "danger",
                        "value": state.request_id,
                        "action_id": "reject",
                    },
                ],
            },
        ]
        await client.chat_postMessage(channel=channel, blocks=blocks)
        print(f"[Slack] Bildirim gönderildi → {channel} | {state.request_id}")
    except Exception as e:
        print(f"[Slack] Hata: {e}")


def create_jira_ticket(state: PentestState, approved: bool = True) -> str:
    """Final rapor sonrası otomatik Jira ticket oluştur."""
    jira_url = os.getenv("JIRA_URL", "")
    jira_user = os.getenv("JIRA_USER", "")
    jira_token = os.getenv("JIRA_API_TOKEN", "")
    jira_project = os.getenv("JIRA_PROJECT", "SEC")
    slack_channel = os.getenv("SLACK_CHANNEL", "#pentest-approvals")

    if not all([jira_url, jira_user, jira_token]):
        print(
            f"[Jira] Jira env eksik — Ticket oluşturulmadı. Request: {state.request_id}"
        )
        return "JIRA_SKIPPED"

    try:
        from jira import JIRA
        from slack_sdk import WebClient

        jira = JIRA(server=jira_url, basic_auth=(jira_user, jira_token))

        summary = (
            f"[Pentest] {state.request_id} - Rapor Hazır "
            f"({'Onaylandı' if approved else 'Revize'})"
        )
        description = (
            f"**Request ID:** {state.request_id}\n"
            f"**Self-Critique Tur:** {state.self_critique_iterations}\n"
            f"**Son Skor:** {state.review_score:.2f}\n"
            f"**Rapor:** reports/{state.request_id}.md\n\n"
            "Otomatik oluşturuldu — SiberEmare Multi-Agent Orchestrator."
        )

        issue = jira.create_issue(
            project=jira_project,
            summary=summary,
            description=description,
            issuetype={"name": "Task"},
            priority={"name": "High" if state.review_score >= 0.98 else "Medium"},
            labels=["pentest", "ai-generated", f"L{state.scope.get('level', '3')}"],
        )

        # Slack notification
        try:
            slack = WebClient(token=os.getenv("SLACK_BOT_TOKEN", ""))
            slack.chat_postMessage(
                channel=slack_channel,
                text=f"✅ Jira Ticket: {jira_url}/browse/{issue.key} | {state.request_id}",
            )
        except Exception:
            pass

        return issue.key
    except Exception as e:
        print(f"[Jira] Hata: {e}")
        return f"JIRA_ERROR: {e}"
