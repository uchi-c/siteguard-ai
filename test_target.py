"""
A deliberately-misconfigured local HTTP server, used ONLY to validate the
scanner's own logic against known-bad conditions (no external network
involved). Not part of the product -- delete or ignore for deployment.
"""
from flask import Flask, make_response

app = Flask(__name__)

@app.route("/")
def home():
    resp = make_response("<html><body><h1>Test Target</h1>"
                          "<script src='http://insecure.example/jquery-1.9.1.min.js'></script>"
                          "</body></html>")
    resp.headers["Server"] = "Apache/2.4.29 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.2.3"
    resp.set_cookie("session", "abc123", secure=False, httponly=False)
    return resp

@app.route("/.env")
def env():
    return "DB_PASSWORD=supersecret123\nAPI_KEY=sk-fake", 200

if __name__ == "__main__":
    app.run(port=5055)
