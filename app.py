
import os
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder=".")

@app.get("/")
def home():
    return send_from_directory(".", "índice.html")

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "app": "NEXUS AI",
        "ai_connected": bool(os.environ.get("GROQ_API_KEY"))
    })

@app.post("/api/ask")
def ask():
    data = request.get_json(silent=True) or {}
    prompt = str(data.get("prompt", "")).strip()

    if not prompt:
        return jsonify({"error": "Escribe una tarea."}), 400

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return jsonify({
            "error": "Falta configurar la IA. Añade GROQ_API_KEY en Render."
        }), 503

    try:
        import requests
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Eres NEXUS AI, un asistente en español "
                            "especializado en programación y ciberseguridad "
                            "defensiva, responsable y legal."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.4
            },
            timeout=45
        )
        response.raise_for_status()
        result = response.json()
        answer = result["choices"][0]["message"]["content"]
        return jsonify({"answer": answer})
    except Exception:
        app.logger.exception("Error al consultar el proveedor de IA")
        return jsonify({
            "error": "No se pudo consultar la IA. Inténtalo de nuevo."
        }), 502

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000"))
    )
