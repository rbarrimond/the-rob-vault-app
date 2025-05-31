'''
A simple Flask app to handle Bungie OAuth authentication.
# bungie_oauth.py'''

import json
import requests
from flask import Flask, request, redirect

# Replace with your actual Bungie app values
CLIENT_ID = "35650"
CLIENT_SECRET = "81db95d78e324528b98c4e0127b874be"
REDIRECT_URI = "http://localhost:5000/auth"

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

    with open("tokens.json", "w") as f:
        json.dump(data, f, indent=2)

    return "✅ Auth successful. Access token saved to tokens.json"

if __name__ == "__main__":
    app.run(port=5000)