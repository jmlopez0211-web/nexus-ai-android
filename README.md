# NEXUS IA — Defensive Intelligence

Panel web de asistencia y diagnóstico defensivo. Diseñado para navegador móvil y escritorio.

## Funciones disponibles

- Asistente IA mediante Groq (requiere `GROQ_API_KEY` en el entorno del servidor).
- Centro Wi-Fi que consulta el puente local Termux:API del teléfono en `127.0.0.1:8765`.
- Auditoría HTTP básica de una única URL pública autorizada:
  - Estado HTTP y cadena de redirecciones limitada.
  - Cabeceras CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy y Permissions-Policy.
  - Atributos Secure, HttpOnly y SameSite de cookies Set-Cookie.
  - Exportación JSON e historial local del navegador.
- Interfaz adaptable, accesible y con ilustración SVG original integrada.

## Auditoría web: alcance y límites

La ruta `POST /api/audit/web` requiere `{"url":"https://example.org/","authorized":true}`.
Solo acepta HTTP/HTTPS y destinos que resuelvan a direcciones IP públicas. Revalida cada redirección,
limita las redirecciones a tres, usa TLS verificado, tiempos de espera acotados y una petición GET
con Range. No rastrea enlaces, no envía formularios, no prueba contraseñas ni ejecuta payloads.
Los resultados son indicios de configuración y deben validarse manualmente; no equivalen a un
pentest ni certifican que el sitio sea seguro.

El análisis remoto no puede alcanzar la LAN privada del teléfono. Para el inventario Wi-Fi y
diagnóstico local se utiliza el puente Termux, que debe permanecer ligado a loopback y no exponerse
a Internet. El navegador puede bloquear solicitudes a localhost desde un sitio HTTPS según las
políticas de origen/red privada del dispositivo.

## Estado de Wapiti

Los archivos fuente Wapiti recibidos se han inspeccionado, pero **el motor Wapiti completo todavía
no está integrado**. Los módulos dependen de todo el paquete `wapitiCore`, datos auxiliares y
dependencias. Antes de incorporarlo hay que integrar la distribución completa, fijar versión,
revisar compatibilidad y cumplir GPLv2. Los módulos de fuerza bruta de formularios quedan excluidos.
No se debe presentar Wapiti como instalado ni operativo en esta versión.

## Desarrollo local

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
```

## Despliegue Render

- Build: `pip install -r requirements.txt`
- Start: `gunicorn main:app`
- Configura `GROQ_API_KEY` como variable secreta solo si vas a usar el asistente.
- No incluyas claves en el repositorio.

## Seguridad y privacidad

- No guardar credenciales ni cookies completas en informes.
- No habilitar análisis de objetivos sin autorización.
- La auditoría web no acepta IP privadas, loopback ni nombres locales.
- El historial del panel se guarda en el almacenamiento local del navegador y puede borrarse desde sus ajustes.
