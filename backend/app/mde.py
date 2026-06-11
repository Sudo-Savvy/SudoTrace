import msal
import httpx
from anthropic import AsyncAnthropic

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


async def test_graph_connection(tenant_id: str, client_id: str, client_secret: str) -> dict:
    try:
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=GRAPH_SCOPES)

        if "access_token" not in result:
            msg = result.get("error_description") or result.get("error") or "Authentication failed."
            return {"ok": False, "error": msg}

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{GRAPH_BASE}/security/runHuntingQuery",
                headers={
                    "Authorization": f"Bearer {result['access_token']}",
                    "Content-Type": "application/json",
                },
                json={"Query": "DeviceInfo | take 1", "Timespan": "P1D"},
            )

        if resp.status_code == 200:
            return {"ok": True}
        if resp.status_code == 403:
            return {
                "ok": False,
                "error": "Connected but ThreatHunting.Read.All permission is missing or admin consent has not been applied.",
            }
        return {"ok": False, "error": f"Unexpected response from Graph API (HTTP {resp.status_code})."}

    except Exception as e:
        return {"ok": False, "error": str(e)}


async def test_anthropic_connection(api_key: str) -> dict:
    try:
        client = AsyncAnthropic(api_key=api_key)
        await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1,
            messages=[{"role": "user", "content": "hi"}],
        )
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}
