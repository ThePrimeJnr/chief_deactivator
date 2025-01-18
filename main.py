import hashlib
import hmac
import os
import random
import re
import time

from fastapi import FastAPI, HTTPException, Request
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from logger import logger

app = FastAPI()
slack = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
SLACK_SIGNING_SECRET = os.environ["SLACK_SIGNING_SECRET"]

SARCASTIC_RESPONSES = [
    "No user or channel? I'm good, but can't read minds. Tag someone properly.",
    "Trying to deactivate a ghost? Mention a real user or channel, boss.",
    "Come on, I'm all for the drama, but at least tell me who's getting canned.",
    "Forgot to tag someone? I'm chill, but not psychic. Let's do it right.",
    "I'd love to help, but next time add @someone or #channel, okay?",
    "Stop practicing invisibility deactivations. Let me know your target.",
    "Authority here: No mention, no action. Tag 'em if you want 'em gone.",
    "That's not how this works. Share who needs deactivating, then we'll talk.",
    "Cool and all, but you must specify a user or channel. Let's keep this official.",
]


@app.post("/deactivate")
async def deactivate(req: Request):
    body = await req.body()

    if not validate_slack_request(req, body):
        raise HTTPException(
            status_code=401, detail="Invalid request signature"
        )

    try:
        payload = await req.form()
        user = slack.users_info(user=str(payload.get("user_id")))
        text = str(payload.get("text", ""))

        if not user["user"]["is_admin"]:
            return {
                "response_type": "ephemeral",
                "text": "Sorry, only admins can use this command.",
            }

        mentions = extract_slack_mentions(text)
        if not text or (not mentions["users"] and not mentions["channels"]):
            return {
                "response_type": "ephemeral",
                "text": random.choice(SARCASTIC_RESPONSES),
            }

        confirm_deactivation(
            str(payload.get("trigger_id")),
            mentions["users"],
            mentions["channels"],
        )
        return {
            "response_type": "in_channel",
            "text": "Awaiting confirmation...",
        }
    except SlackApiError as e:
        logger.error(f"Error posting message: {e.response['error']}")
        return {
            "response_type": "ephemeral",
            "text": "Something went wrong. Please try again later.",
        }


def validate_slack_request(request: Request, body: bytes) -> bool:
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")

    if abs(time.time() - float(timestamp)) > 60 * 5:
        return False

    sig_basestring = f"v0:{timestamp}:{body.decode()}"

    my_signature = (
        "v0="
        + hmac.new(
            SLACK_SIGNING_SECRET.encode(),
            sig_basestring.encode(),
            hashlib.sha256,
        ).hexdigest()
    )

    return hmac.compare_digest(my_signature, signature)


def extract_slack_mentions(text: str) -> dict:
    users = set()
    channels = set()
    mention_pattern = r"<(@U[A-Z0-9]+|#C[A-Z0-9]+)(?:\|[^>]+)?>"
    matches = re.finditer(mention_pattern, text)
    for match in matches:
        identifier = match.group(1)
        if identifier.startswith("@U"):
            users.add(identifier[1:])
        elif identifier.startswith("#C"):
            channels.add(identifier[1:])
    return {"users": list(users), "channels": list(channels)}


def confirm_deactivation(trigger_id: str, user_ids: list, channel_ids: list):
    sections = []
    if user_ids:
        user_list = " ".join(f"<@{u}>" for u in user_ids)
        sections.append(f"*Users:*\n• {user_list}")

    if channel_ids:
        channel_list = " ".join(f"<#{c}>" for c in channel_ids)
        sections.append(f"*Channel Members:*\n• {channel_list}")

    summary = (
        "You are about to *deactivate* the following:\n\n"
        + "\n\n".join(sections)
        + "\n\n_*Warning:* This action cannot be undone_"
    )

    slack.views_open(
        trigger_id=trigger_id,
        view={
            "type": "modal",
            "title": {"type": "plain_text", "text": "Confirm Deactivation"},
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": summary,
                    },
                },
            ],
            "submit": {"type": "plain_text", "text": "Yes, Deactivate"},
            "close": {"type": "plain_text", "text": "Cancel"},
        },
    )
