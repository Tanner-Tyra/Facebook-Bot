# flask_tunnel.py
import asyncio
from waitress import serve
from cloudflarify import start_tunnel
from flask import Flask, request
import requests
import os


def name_find(sender_id):
    try:
        r = requests.get(
            f'https://graph.facebook.com/{sender_id}?fields=first_name,last_name&access_token={PAGE_ACCESS_TOKEN}'
        ).json()
        return [r.get('first_name', ''), r.get('last_name', '')]
    except Exception as e:
        print(f"[!] Failed to fetch name for {sender_id}: {e}")
        return ["Unknown", "User"]



app = Flask(__name__)
VERIFY_TOKEN = "token" # Put in facebook verification token
PAGE_ACCESS_TOKEN = "token" # put in page access token
API_KEY = 'key'  # Replace with your actual API key
API_URL = 'link' # put in Apologist AI API link

@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        if mode == 'subscribe' and token == VERIFY_TOKEN:
            return challenge, 200
        else:
            return 'Forbidden', 403
    if request.method == 'POST':
        data = request.get_json()
        print("Webhook POST payload:", data)
        if data.get("object") == "page":
            for entry in data["entry"]:
                for messaging_event in entry.get("messaging", []):
                    sender_id = messaging_event["sender"]["id"]
                    if os.path.exists("Users.txt"):
                        with open("Users.txt", "r") as f:
                            parsed = [i.split(":") for i in f.readlines()]
                            parsed = {i[0]: i[-1] for i in parsed}
                            if sender_id in parsed.keys():
                                if parsed[sender_id] == "yes":
                                    if "message" in messaging_event and "text" in messaging_event["message"]:
                                        message_text = messaging_event["message"]["text"]
                                        if os.path.exists(rf"conversations\{sender_id}.txt"):
                                            with open(rf"conversations\{sender_id}.txt", "r") as l:
                                                messages = "\n".join(l.readlines()).split("|||||")
                                                messages = [
                                                    {"role": "user" if i % 2 == 0 else "assistant", "content": messages[i]}
                                                    for i in range(len(messages))
                                                ]
                                            messages.append({"role":"user", "content":message_text})
                                            response = get_gospelbot_reply(messages)
                                            messages.append({"role": "assistant", "content": response})
                                            with open(rf"conversations\{sender_id}.txt", "w") as l:
                                                for i in messages:
                                                    l.write(i["content"] + "|||||" + "\n")
                                            send_message(sender_id, response)
                            else:
                                if "message" in messaging_event and "text" in messaging_event["message"]:
                                    name = name_find(sender_id)
                                    with open("Users.txt", "a", encoding="utf-8") as m:
                                        m.write(f"{sender_id}:{name[0]}:{name[1]}:yes\n")
                                    message_text = messaging_event["message"]["text"]
                                    messages = [{"role":"user", "content": message_text}]
                                    response = get_gospelbot_reply(messages)
                                    messages.append({"role": "assistant", "content": response})
                                    thing = os.path.join("conversations", f"{sender_id}.txt")
                                    with open(thing, "w") as m:
                                        for i in messages:
                                            m.write(i["content"] + "|||||" + "\n")
                                    send_message(sender_id, response)

        return "EVENT_RECEIVED", 200
def send_message(recipient_id, message_text):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": message_text}
    }
    response = requests.post(url, json=payload)
    print(f"📤 Sent message to {recipient_id}: {message_text}")
    print("🛠 Facebook response:", response.text)

def get_gospelbot_reply(messages):
    headers = {
        'x-api-key': API_KEY,
        'Content-Type': 'application/json'
    }

    payload = {
        "model": "openai/gpt/4o",
        "stream": False,
        "messages": messages,
        "response_format": {"type": "json"},
        "metadata": {
            "anonymous": True,
            "conversation": None,
            "language": "en",
            "session": None,
            "translation": "esv"
        },
        "frequency_penalty": 0.25,
        "presence_penalty": -0.25,
        "max_completion_tokens": 1024,
        "reasoning_effort": "high",
        "temperature": 0.5,
        "top_p": 0.9,
        "user": None
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload)
        response.raise_for_status()
        result = response.json()
        return result.get("choices", [{}])[0].get("message", {}).get("content", "[No reply]")
    except Exception as e:
        return f"[Error]: {str(e)}"

async def main():
    # Start the Flask server in a background thread
    import threading
    def run_server():
        serve(app, host="0.0.0.0", port=5000)
    threading.Thread(target=run_server, daemon=True).start()

    # Wait a moment for the server to start
    await asyncio.sleep(2)

    # Start Cloudflare tunnel
    tunnel_url = await start_tunnel(app_port=5000)
    print("Tunnel URL:", tunnel_url)
    with open("current_url.txt", "w") as t:
        t.write(tunnel_url)
    print(f"Use this URL + '/webhook' as your Facebook webhook callback URL.")

    # Keep running so Flask and tunnel stay alive
    while True:
        await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(main())
