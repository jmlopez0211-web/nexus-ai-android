import os
from flask import Flask, request, jsonify, send_from_directory
from groq import Groq

app = Flask(__name__, static_folder=".", static_url_path="")

@app.get("/")
def inicio():
    # Serve the actual Spanish-named frontend file in this repository.
    return send_from_directory(".", "índice.html")

@app.get("/api/estado")
@app.get("/api/health")
def estado():
    configured = bool(os.environ.get("GROQ_API_KEY"))
    return jsonify({
        "ok": True,
        "status": "ok",
        "app": "NEXUS AI",
        "ia_configurada": configured,
        "ai_connected": configured
    })

@app.post("/api/ia")
@app.post("/api/ask")
def consultar_ia():
    clave = os.environ.get("GROQ_API_KEY")
    if not clave:
        return jsonify({"error": "Falta configurar GROQ_API_KEY en Render."}), 503

    datos = request.get_json(silent=True) or {}
    tarea = str(datos.get("tarea", "")).strip()
    if not tarea:
        return jsonify({"error": "Escribe una tarea primero."}), 400

    try:
        cliente = Groq(api_key=clave)
        respuesta = cliente.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres NEXUS AI, un asistente responsable, útil y orientado "
                        "a la seguridad defensiva. Responde en español y explica "
                        "los pasos con claridad."
                    )
                },
                {"role": "user", "content": tarea}
            ],
            temperature=0.4,
            max_tokens=1200
        )
        texto = respuesta.choices[0].message.content
        return jsonify({"respuesta": texto})
    except Exception:
        app.logger.exception("Error consultando el modelo de IA")
        return jsonify({
            "error": "No se pudo consultar la IA. Revisa la clave y los registros de Render."
        }), 502

if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=puerto)
