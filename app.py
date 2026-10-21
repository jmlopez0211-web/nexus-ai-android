
import os
from flask import Flask, jsonify, send_from_directory

app = Flask(__name__, static_folder=".")

@app.route("/")
def home():
    return send_from_directory(".", "index.html")

@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "NEXUS AI",
        "ai_connected": False
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
