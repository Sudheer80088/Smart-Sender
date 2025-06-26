from flask import Flask, request, jsonify, session
from flask_session import Session
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import os
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = "your-secret-key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
CORS(app)

SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        redirect_uri="https://smart-backend.onrender.com/oauth2callback"
    )
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")
    return jsonify({"auth_url": auth_url})

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        "client_secret.json",
        scopes=SCOPES,
        redirect_uri="https://smart-backend.onrender.com/oauth2callback"
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)
    session["user_email"] = credentials.id_token.get("email")
    return "Login successful! You can close this tab and return to the app."

@app.route("/send_emails", methods=["POST"])
def send_emails():
    if "credentials" not in session:
        return jsonify({"error": "User not authenticated."}), 401

    data = request.get_json()
    emails = data.get("emails", [])
    message = data.get("message", "")
    subject = data.get("subject", "")
    schedule = data.get("schedule", "")

    results = []
    for entry in emails:
        to_email = entry.get("email")
        name = entry.get("name", "")
        personalized_message = message.replace("{First Name}", name or "there")
        result = send_email(
            session["user_email"],
            session["credentials"],
            to_email,
            subject,
            personalized_message
        )
        results.append(result)
    return jsonify({"status": "done", "results": results})

def send_email(user_id, creds_dict, to_email, subject, message_text):
    try:
        creds = Credentials.from_authorized_user_info(info=creds_dict, scopes=SCOPES)
        service = build("gmail", "v1", credentials=creds)
        message = {
            "raw": create_message(user_id, to_email, subject, message_text)
        }
        result = service.users().messages().send(userId="me", body=message).execute()
        return {"status": "sent", "to": to_email, "id": result.get("id")}
    except Exception as e:
        return {"status": "error", "to": to_email, "error": str(e)}

def create_message(sender, to, subject, message_text):
    import base64, email.mime.text
    message = email.mime.text.MIMEText(message_text)
    message["to"] = to
    message["from"] = sender
    message["subject"] = subject
    return base64.urlsafe_b64encode(message.as_bytes()).decode()

def credentials_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes
    }

if __name__ == "__main__":
    app.run(debug=True)
