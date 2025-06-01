import os
import json
import requests
from flask import Flask, request, redirect

# Read sensitive values from environment variables
CLIENT_ID = os.environ.get("BUNGIE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("BUNGIE_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("BUNGIE_REDIRECT_URI", "")

app = Flask(__name__)

@app.route("/")
def home():
    return redirect(
        f"https://www.bungie.net/en/OAuth/Authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}"
    )

@app.route("/auth")
def auth():
    code = request.args.get("code")
    token_url = "https://www.bungie.net/platform/app/oauth/token/"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(token_url, data=payload, headers=headers)
    data = res.json()

    # For demo: print token data (do not use print in production)
    print(json.dumps(data, indent=2))

    return "✅ Auth successful. Access token received."

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)