import os
from flask import Flask, request, jsonify, send_from_directory
from groq import Groq
from requests import RequestException

from audit_engine import AuditInputError, audit_url

app = Flask(__name__, static_folder=".", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.get("/")
def inicio():
    return send_from_directory(".", "índice.html")


@app.get("/api/estado")
@app.get("/api/health")
def estado():
    configured = bool(os.environ.get("GROQ_API_KEY"))
    return jsonify({
        "ok": True,
        "status": "ok",
        "app": "NEXUS AI",
        "ai_configured": configured,
        # A configured API key is not proof of upstream connectivity.
        "ai_connected": None
    })


@app.post("/api/audit/web")
def auditar_web():
    datos = request.get_json(silent=True) or {}
    if datos.get("authorized") is not True:
        return jsonify({"error": "Confirma que eres propietario del sitio o tienes autorización expresa."}), 403
    url = str(datos.get("url", "")).strip()
    if not url:
        return jsonify({"error": "Indica la URL que quieres revisar."}), 400
    try:
        resultado = audit_url(url)
        resultado["audit_type"] = "single_url_http_posture"
        resultado["authorized_by_user"] = True
        return jsonify(resultado)
    except AuditInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except RequestException:
        app.logger.exception("Fallo de red durante la auditoría web")
        return jsonify({"error": "No se pudo conectar con el sitio. Comprueba la URL, TLS y disponibilidad."}), 502
    except Exception:
        app.logger.exception("Error inesperado en auditoría web")
        return jsonify({"error": "La auditoría no pudo completarse. Revisa los registros del servidor."}), 500


@app.post("/api/ia")
@app.post("/api/ask")
def consultar_ia():
    clave = os.environ.get("GROQ_API_KEY")
    if not clave:
        return jsonify({"error": "Falta configurar GROQ_API_KEY en el servidor."}), 503

    datos = request.get_json(silent=True) or {}
    tarea = str(datos.get("tarea", "")).strip()
    if not tarea:
        return jsonify({"error": "Escribe una tarea primero."}), 400
    if len(tarea) > 12000:
        return jsonify({"error": "La consulta supera el límite de 12.000 caracteres."}), 413

    try:
        cliente = Groq(api_key=clave)
        respuesta = cliente.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Eres NEXUS AI, un asistente responsable de seguridad defensiva. "
                        "Responde en español. Prioriza sistemas propios o con autorización, "
                        "diagnóstico, mitigación y explicación clara. No facilites robo de "
                        "credenciales, acceso no autorizado ni fuerza bruta."
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
            "error": "No se pudo consultar la IA. Revisa la clave y los registros del servidor."
        }), 502


if __name__ == "__main__":
    puerto = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=puerto)
