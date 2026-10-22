import os
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
import requests

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__, static_folder=None)
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response
@app.route("/", methods=["GET"])
def home():
    return send_from_directory(str(BASE_DIR), "índice.html")

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "app": "NEXUS AI",
        "ai_connected": bool(os.environ.get("GROQ_API_KEY"))
    })

@app.route("/api/ask", methods=["POST"])
def ask():
    data = request.get_json(silent=True) or {}
    task = str(data.get("task") or data.get("tarea") or data.get("prompt") or data.get("mensaje") or "").strip()

    if not task:
        return jsonify({"error": "Escribe una tarea."}), 400

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({"error": "Falta configurar GROQ_API_KEY en Render."}), 503

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "openai/gpt-oss-20b",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Eres NEXUS AI, un asistente en español "
                            "especializado en programación, tecnología "
                            "y ciberseguridad defensiva y legal."
                        )
                    },
                    {"role": "user", "content": task}
                ],
                "temperature": 0.4
            },
            timeout=45
        )
        response.raise_for_status()
        result = response.json()
        
        
        answer = result["choices"][0]["message"]["content"]
        return jsonify({"respuesta": answer})
    except requests.RequestException:
        app.logger.exception("Error consultando Groq")
        return jsonify({"error": "No se pudo consultar la IA. Inténtalo de nuevo."}), 502
    except (KeyError, IndexError, TypeError, ValueError):
        app.logger.exception("Respuesta inesperada de Groq")
        return jsonify({"error": "La respuesta de la IA no tiene el formato esperado."}), 502

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
