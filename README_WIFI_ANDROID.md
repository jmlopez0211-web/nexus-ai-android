# NEXUS IA — conexión Wi-Fi local con Termux

Este puente permite que el botón Wi-Fi de NEXUS IA consulte el inventario de redes que devuelve Termux:API en el mismo teléfono Android.

## Requisitos
- Android con Termux y Termux:API instalados desde fuentes compatibles entre sí.
- En Termux: `pkg install python termux-api`.
- Permisos de Android para Termux:API; la disponibilidad del escaneo depende de la versión de Android, permisos y restricciones del fabricante.

## Arranque
1. Copia `nexus_wifi_bridge.py` en Termux.
2. (Recomendado) Define un token local: `export NEXUS_WIFI_TOKEN='elige-un-token-largo'`.
3. Inicia: `python nexus_wifi_bridge.py`.
4. En NEXUS IA abre **Wi-Fi seguro**, deja la dirección `http://127.0.0.1:8765`, introduce el token si configuraste uno y pulsa **Buscar redes reales**.

La web NEXUS alojada en Render debe poder acceder al loopback del teléfono desde el navegador. Chrome puede aplicar controles adicionales de acceso a red local; si el navegador lo bloquea, utiliza la interfaz PWA servida localmente en el mismo teléfono o revisa el permiso que muestre el navegador.

## Seguridad y límites
- El servidor escucha exclusivamente en `127.0.0.1`; no cambies HOST a `0.0.0.0`, no reenvíes el puerto y no lo publiques.
- La lista CORS contiene el origen de NEXUS y los orígenes localhost habituales. Puedes añadir otros orígenes exactos con `NEXUS_WIFI_ALLOWED_ORIGINS` separados por comas.
- El token es opcional, pero se recomienda configurarlo. No lo compartas ni lo incluyas en repositorios.
- Solo ofrece inventario de redes anunciado por Termux:API. No recupera, prueba ni almacena contraseñas Wi-Fi.
- El botón exporta el inventario recibido; los resultados no son una auditoría completa de vulnerabilidades.
- La detección automática de aplicaciones instaladas y el acceso a funciones Android protegidas requieren una app Android nativa con permisos explícitos.
