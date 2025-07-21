# Import necessary modules
from cryptography.fernet import Fernet           # For encryption/decryption
import asyncio                                    # For asynchronous operations
import hashlib, hmac                              # For signature verification
from datetime import datetime, timezone           # For timestamp handling

import requests                                   # To make external HTTP requests
from cloudflarify import start_tunnel             # Starts Cloudflare tunnel
from flask import Flask, request, abort           # Web framework and request parsing
from waitress import serve                        # Production-ready WSGI server
from sql_database import SessionLocal, User, Message  # SQLAlchemy DB models/session
from sqlalchemy.exc import SQLAlchemyError        # Exception class for DB errors

# Load and initialize encryption key
with open("Encryption_key.txt", "rb") as l:
    key = l.read().strip()
cipher = Fernet(key)
del key

# Encryption helper functions
def encrypt_txt(txt):
    return cipher.encrypt(txt.encode()).decode()

def decrypt_txt(txt):
    return cipher.decrypt(txt.encode()).decode()

# Facebook signature verification to confirm request authenticity
def verify_fb_signature(fb_request):
    signature_256 = fb_request.headers.get('X-Hub-Signature-256')
    if signature_256:
        try:
            sha_name, signature_hash = signature_256.split("=")
        except ValueError:
            abort(403)
        if sha_name != 'sha256':
            abort(403)
        mac = hmac.new(APP_SECRET.encode('utf-8'), msg=request.data, digestmod=hashlib.sha256)
        if not hmac.compare_digest(mac.hexdigest(), signature_hash):
            abort(403)
        return

    # Fallback for older signature format
    signature = fb_request.headers.get('X-Hub-Signature')
    if signature:
        try:
            sha_name, signature_hash = signature.split('=')
        except ValueError:
            abort(403)
        if sha_name != 'sha1':
            abort(403)
        mac = hmac.new(APP_SECRET.encode(), msg=request.data, digestmod=hashlib.sha1)
        if not hmac.compare_digest(mac.hexdigest(), signature_hash):
            abort(403)
        return
    abort(403)  # Reject if no valid signature

# Get user's first and last name from Facebook Graph API
def name_find(sender_id):
    try:
        r = requests.get(
            f'https://graph.facebook.com/{sender_id}?fields=first_name,last_name&access_token={PAGE_ACCESS_TOKEN}'
        ).json()
        return [r.get('first_name', ''), r.get('last_name', '')]
    except Exception as e:
        print(f"[!] Failed to fetch name for {sender_id}: {e}")
        return ["Unknown", "User"]

# Initialize Flask app
app = Flask(__name__)

# Load credentials and config values from file
with open("Facebook_stuff.txt", "r") as l:
    key = l.readlines()
    PAGE_ID           = key[5]
    VERIFY_TOKEN      = key[0]
    APP_ID            = key[4]
    APP_SECRET        = key[3]
    APP_ACCESS_TOKEN  = f"{APP_ID}|{APP_SECRET}"
    PAGE_ACCESS_TOKEN = key[1]
    API_KEY           = key[2]
    API_URL           = key[6]
del key

# Health check route to monitor service availability
@app.route("/health", methods=["GET"])
def health_check():
    try:
        session = SessionLocal()
        session.execute("SELECT 1")  # Lightweight ping to DB
        session.close()
        return "OK", 200
    except SQLAlchemyError:
        return "Database Unavailable", 500

# Main webhook handler
@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    try:
        if request.method == 'GET':
            # Facebook webhook verification
            mode = request.args.get('hub.mode')
            token = request.args.get('hub.verify_token')
            challenge = request.args.get('hub.challenge')
            if mode == 'subscribe' and token == VERIFY_TOKEN:
                return challenge, 200
            else:
                return 'Forbidden', 403

        if request.method == 'POST':
            verify_fb_signature(request)  # Verify authenticity
            data = request.get_json()
            print("Webhook POST payload:", data)

            if data.get("object") == "page":
                session = SessionLocal()
                try:
                    for entry in data.get("entry", []):
                        for messaging_event in entry.get("messaging", []):
                            sender_id = messaging_event["sender"]["id"]

                            # Find or create user
                            user = session.query(User).filter_by(id=sender_id).first()
                            if not user:
                                name = name_find(sender_id)
                                user = User(
                                    id=sender_id,
                                    first_name=encrypt_txt(name[0]),
                                    last_name=encrypt_txt(name[1]),
                                    approved="yes"
                                )
                                session.add(user)
                                session.commit()

                            # Only respond if user is approved and sent 12 or fewer messages
                            if user.approved.lower() == "yes":
                                if session.query(Message).filter_by(sender_id=sender_id, role='user').count() <= 12:
                                    if "message" in messaging_event and "text" in messaging_event["message"]:
                                        message_text = messaging_event["message"]["text"]

                                        # Get user message history
                                        messages = (
                                            session.query(Message)
                                            .filter_by(sender_id=sender_id)
                                            .order_by(Message.created_at.asc())
                                            .all()
                                        )
                                        history = [{"role": m.role, "content": decrypt_txt(m.content)} for m in messages]
                                        history.append({"role": "user", "content": message_text})

                                        # Call GospelBot API
                                        while True:
                                            try:
                                                response = get_gospelbot_reply(history)
                                                break
                                            except:
                                                pass
                                        history.append({"role": "assistant", "content": response})

                                        # Save new messages to DB
                                        session.add(Message(
                                            sender_id=sender_id,
                                            role=history[-2]["role"],
                                            content=encrypt_txt(history[-2]["content"]),
                                            created_at=datetime.now(timezone.utc)
                                        ))
                                        session.add(Message(
                                            sender_id=sender_id,
                                            role=history[-1]["role"],
                                            content=encrypt_txt(history[-1]["content"]),
                                            created_at=datetime.now(timezone.utc)
                                        ))
                                        session.commit()

                                        # Send reply back via Messenger
                                        send_message(sender_id, response)

                    return "EVENT_RECEIVED", 200
                finally:
                    session.close()
            else:
                return "Not Found", 404
        else:
            return "Method Not Allowed", 405
    except Exception as e:
        return "Internal Server Error", 500

# Function to send a message using Facebook Messenger API
def send_message(recipient_id, message_text):
    url = f"https://graph.facebook.com/v19.0/me/messages?access_token={PAGE_ACCESS_TOKEN}"
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": message_text}
    }
    response = requests.post(url, json=payload)
    print(f"📤 Sent message to {recipient_id}: {message_text}")
    print("🛠 Facebook response:", response.text)

# Function to get GospelBot response from custom API
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

# Main async runner: launches the Flask server and Cloudflare tunnel
async def main():
    # Start Flask server in background thread
    import threading
    def run_server():
        serve(app, host="0.0.0.0", port=5000)
    threading.Thread(target=run_server, daemon=True).start()

    await asyncio.sleep(2)  # Give server time to start

    # Launch Cloudflare tunnel
    tunnel_url = await start_tunnel(app_port=5000)
    print("Tunnel URL:", tunnel_url)
    with open("current_url.txt", "w") as t:
        t.write(tunnel_url)
    print(f"Use this URL + '/webhook' as your Facebook webhook callback URL.")

    # Keep script alive indefinitely
    while True:
        await asyncio.sleep(60)

# Entry point
if __name__ == "__main__":
    asyncio.run(main())
