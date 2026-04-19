from flask import Flask, request, jsonify
import os

app = Flask(__name__)

API_KEY = os.getenv("API_KEY")

@app.route("/")
def home():
    return "🚀 API Running"

@app.route("/api", methods=["GET"])
def api():
    auth = request.headers.get("Authorization")

    if auth != f"Bearer {API_KEY}":
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "status": "success",
        "message": "API working 🔥"
    })