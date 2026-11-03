# NEXUS IA — Defensive Intelligence

Panel web de asistencia y diagnóstico defensivo. Diseñado para navegador móvil y escritorio.

## Funciones disponibles

- Asistente IA mediante Groq (requiere `GROQ_API_KEY` en el entorno del servidor).
- Centro Wi-Fi que consulta el puente local Termux:API del teléfono en `127.0.0.1:8766`.
- Auditoría HTTP básica de una única URL pública autorizada:
  - Estado HTTP y cadena de redirecciones limitada.
  - Cabeceras CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy y Permissions-Policy.
  - Atributos Secure, HttpOnly y SameSite de cookies Set-Cookie.
  - Exportación JSON e historial local del navegador.
- Interfaz adaptable, accesible y con ilustración SVG original integrada.

## Puente local Android/Termux

El repositorio incorpora `nexus_bridge_termux.py`, independiente del puente antiguo de SCANNER OF DEATH.
En Termux, dentro de la carpeta del repositorio:

```bash
python nexus_bridge_termux.py
```

El proceso escucha exclusivamente en `127.0.0.1:8766` y muestra un token de sesión en la terminal.
Introduce `http://127.0.0.1:8766` y ese token en el Centro Wi-Fi de NEXUS. No publiques ni reenvíes
ese puerto. El puente ofrece:

- `GET /api/status`: estado del puente.
- `GET /api/tooling`: inventario de solo lectura del motor Python, herramientas inalámbricas detectadas y capacidades visibles del entorno.
- `GET /api/wifi`: lectura de redes cercanas mediante Termux:API, si está instalada y autorizada.
- `POST /api/scan`: inventario TCP de un único IPv4 privado autorizado, limitado a 20 puertos habituales.

El escaneo de puertos no recorre rangos ni subredes, no prueba contraseñas y no identifica versiones.
El nombre del servicio se infiere del puerto; un puerto abierto no demuestra por sí solo una vulnerabilidad.
El puente valida la IP privada, requiere el token y confirmación de autorización, aplica una lista CORS
limitada y solo escucha en loopback. Si el navegador bloquea el acceso HTTPS a localhost por sus políticas
de red privada, el panel indicará el error; no se debe exponer el puente a Internet como solución.

## Motor Python independiente

El módulo `nexus_wireless_engine.py` funciona separado de la interfaz y usa la biblioteca estándar de Python. El panel consulta el endpoint autenticado `GET /api/tooling` del puente local y permite exportar el diagnóstico JSON.

El catálogo incluye Wacker, hostapd-mana, Wifite2 y EAPHammer. La comprobación únicamente busca sus ejecutables en el PATH: no los instala ni los ejecuta. El informe muestra la versión de Python, arquitectura, disponibilidad de Termux:API e interfaces Wi-Fi visibles. La visibilidad de una interfaz no demuestra compatibilidad con modo monitor ni inyección de paquetes; esos campos permanecen sin verificar.

Este módulo no inicia puntos de acceso, no suplanta redes, no captura credenciales o autenticaciones y no realiza intentos de contraseña. Para revisar el funcionamiento:

```bash
python -m unittest discover -s tests -v
python -c "from nexus_wireless_engine import inventory_tools; print(inventory_tools())"
```

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

## Auditoría defensiva Wi-Fi

El Centro Wi-Fi incluye un análisis pasivo de los anuncios recibidos por Termux:API:
- Clasifica anuncios WPA3, WPA2, modos mixtos, WPA heredado, WEP, redes abiertas explícitas y capacidades desconocidas (que no se confunden con redes abiertas).
- Señala WPS anunciado y ofrece recomendaciones de configuración.
- Resume intensidad de señal y frecuencia.
- Exporta un informe JSON local.

Incluye además una comprobación offline de la contraseña de una red que el usuario controla. La compara con una pequeña lista integrada de claves habituales y, opcionalmente, con un diccionario .txt elegido por el usuario (máximo 5 MB). Todo se procesa en el navegador: la contraseña se borra del campo al terminar y no se transmite ni se guarda. Es una comparación exacta de texto y una heurística orientativa, no una estimación criptográfica de entropía.

**Límites deliberados:** no captura handshakes, no recupera claves de redes, no ejecuta fuerza bruta ni ataques de diccionario contra puntos de acceso, no intenta autenticarse ni lanza intentos de contraseña contra ninguna red. La lista integrada es breve y no exhaustiva; una ausencia de coincidencia no demuestra que la contraseña sea segura. El análisis Wi-Fi se basa únicamente en metadatos anunciados y no demuestra que una red sea vulnerable. WPS anunciado es un indicador para revisar, no una vulnerabilidad confirmada.

### Laboratorio Wi-Fi simulado

El panel incluye un simulador local de intentos con una clave ficticia y una lista de ejemplos editable. Permite observar el efecto de un bloqueo tras varios fallos y exportar un informe marcado como simulado. El procesamiento ocurre íntegramente en el navegador: no utiliza el adaptador Wi-Fi, no contacta con un punto de acceso, no transmite credenciales y no demuestra la seguridad de un router real.

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
