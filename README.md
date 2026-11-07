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

El proceso escucha exclusivamente en `127.0.0.1:8766`. El token persistente se crea o carga desde `~/.nexus_bridge_token` y no se imprime en pantalla. Para copiarlo al portapapeles de Termux sin mostrarlo, ejecuta `termux-clipboard-set "$(cat ~/.nexus_bridge_token)"`. En NEXUS introduce `http://127.0.0.1:8766`, pega el token y pulsa **Guardar dirección**. El panel guarda primero las credenciales y después verifica la conexión. No publiques ni reenvíes ese puerto. El puente ofrece:

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


## Auditoría local detallada HTTP/TLS

La ruta autenticada `POST /api/audit` amplía el inventario TCP de un único equipo IPv4 privado con una inspección defensiva de los servicios web encontrados en los puertos HTTP/HTTPS incluidos en la lista NEXUS.

- Requiere el mismo token local y `authorized: true` que el escaneo TCP existente.
- Solo consulta `GET /` sin credenciales, no sigue redirecciones y no lee ni almacena el cuerpo de la respuesta.
- Recoge una lista limitada de cabeceras de seguridad, atributos de cookies (nunca sus valores) y metadatos públicos del certificado TLS.
- La validación TLS estándar se informa separadamente. Si falla, la conexión sin validar se utiliza solo para inspeccionar metadatos públicos; nunca se envían credenciales.
- Los hallazgos se etiquetan como observaciones de configuración, validación de confianza o comprobaciones incompletas. No se presentan como vulnerabilidades confirmadas.
- La interfaz permite exportar JSON y HTML, además de abrir una vista imprimible que el navegador puede guardar como PDF.
- El alcance sigue limitado a una sola IPv4 RFC1918 y a los puertos TCP predefinidos. No recorre subredes ni intenta iniciar sesión.

Los informes excluyen valores de cookies, tokens, contraseñas y cuerpos de respuesta. La inspección no modifica el equipo auditado.


## Seguimiento de cambios y línea base local

La ruta autenticada `POST /api/audit/compare` ejecuta la auditoría defensiva de un único IPv4 privado y compara el resultado con la última línea base local del mismo equipo.

- La primera ejecución crea una línea base; no inventa cambios cuando aún no existe una referencia.
- Las siguientes ejecuciones detectan puertos TCP que aparecen o dejan de responder, cambios de huella SHA-256 del certificado TLS, fechas/sujeto/emisor del certificado, estado TLS, cabeceras HTTP, cookies (solo nombre y atributos) y estado HTTP.
- Cada diferencia incluye evidencia, clasificación, nivel de confianza y recomendación. Un cambio observado no se etiqueta automáticamente como vulnerabilidad.
- La línea base se guarda solo en Termux en `~/.cache/nexus-ai/security-baselines/`, con permisos privados y escritura atómica. No se guardan cuerpos HTTP, valores de cookies ni credenciales.
- La interfaz ofrece JSON y HTML; la vista de impresión permite guardar el informe como PDF desde el navegador.
- La comparación es entre la última auditoría y la anterior. No es un histórico inmutable ni una vigilancia continua; hay que ejecutar una nueva comparación para actualizar la referencia.


## Centro de motores y diagnóstico Android

La interfaz añade el **Centro completo de motores**. Consulta el puente local autenticado:

- `GET /api/engines`: inventario de intérpretes, motores SQL, módulos Python del proyecto, dependencias, herramientas y plugins registrados.
- `GET /api/diagnostics`: autodiagnóstico de solo lectura.
- `POST /api/engines/run`: prueba fija y autorizada de un motor disponible. No acepta comandos arbitrarios.
- `POST /api/maintenance/repair`: prepara exclusivamente directorios privados de datos de NEXUS y requiere `{"confirmed":true}`.

El catálogo detecta Python, Node.js, Bash, PHP, Java, Ruby, Perl, Lua, R, Go, Rust y compiladores C/C++ cuando están instalados. SQL incluye SQLite, DuckDB, PostgreSQL y MySQL/MariaDB. La lista de herramientas detecta Nmap, Aircrack-ng, utilidades inalámbricas, OpenSSL, clientes SQL y componentes Greenbone/OpenVAS y Wapiti sin ejecutarlos.

**Límites de reparación:** desde la interfaz se pueden diagnosticar y reparar carpetas de datos propias de NEXUS. No se instalan dependencias ni se modifican scripts, permisos del sistema o ajustes de Android automáticamente. Si el puente local está detenido, el navegador no puede iniciarlo por sí solo: Android mantiene aislados los procesos de Termux. La recuperación de un puente detenido necesita un mecanismo de arranque de Android previamente configurado o una intervención local.

Las pruebas de motor usan órdenes fijas de versión o pruebas inocuas. SQLite y DuckDB usan bases de datos en memoria; PostgreSQL y MySQL se inventarían, pero no se conectan sin una configuración explícita. Los plugins existentes conservan su aprobación individual y se ejecutan con los permisos de Termux; el lanzador no es un sandbox.

El inventario también enumera las distribuciones instaladas en el intérprete Python activo y detecta las distros Proot presentes en el directorio estándar de Termux. La presencia de un ejecutable Python dentro de un rootfs se etiqueta como detectada, no como ejecución verificada: NEXUS no inicia automáticamente Ubuntu/Debian ni cambia sus entornos.

El panel ofrece además una reparación de dependencias Python ausentes, con confirmación explícita. Solo instala las dependencias principales de NEXUS que no se detectan (Flask, Groq, Requests y Gunicorn); no ejecuta actualizaciones deliberadas de paquetes que ya están instalados. El proceso tiene límite de tiempo y registra el resultado sin mostrar claves.


## Arranque automático y recuperación Android

Consulta [README_TERMUX_AUTOSTART.md](README_TERMUX_AUTOSTART.md) para instalar Termux:Boot, el supervisor de reinicio y la comprobación de salud. Requiere una instalación inicial única en Termux por el aislamiento de aplicaciones de Android; después el arranque y la recuperación del puente son automáticos.


## Recuperación guiada de routers

El Centro Wi-Fi incorpora una guía local para recuperar el acceso a routers propios o autorizados cuando se ha perdido la clave y no hay dispositivos conectados. Recoge operador, fabricante, modelo y situación de acceso; orienta sobre etiqueta del equipo, app/área de cliente, administración legítima y restablecimiento de fábrica como último recurso. Incluye una lista de pasos verificables y exportación JSON o impresión/PDF.

- No solicita, almacena ni exporta contraseñas, claves administrativas ni números de serie.
- No extrae ni descifra credenciales guardadas y no se conecta ni modifica el router.
- Advierte que el restablecimiento puede borrar parámetros de Internet, telefonía, IPTV y configuración personalizada; se debe confirmar el procedimiento con el operador.
- El informe documenta la guía y el estado marcado por el usuario; no certifica que la recuperación haya funcionado hasta verificar la conexión y los servicios.


## R2SU — Programador y ejecutor de tareas NEXUS

R2SU es el programador persistente del núcleo Python. Se inicia junto con el puente Termux y conserva tareas e historial en SQLite local (`~/.cache/nexus-ai/r2su.sqlite3`, permisos privados). API autenticada del puente:

- `GET /api/r2su`: estado, tareas e historial.
- `POST /api/r2su`: acciones `create`, `run`, `pause`, `resume`, `delete`, `start` y `stop`.

Tipos de tarea disponibles:
- `runtime_diagnostics`: diagnóstico del entorno Python/Android.
- `wifi_inventory`: consulta Termux:API; lee los últimos resultados Android y no fuerza un escaneo de radio.
- `lan_scan`: inventario TCP de un único IPv4 privado RFC1918; requiere `params.authorized=true`.

Ejemplo de creación de una tarea periódica (la solicitud debe incluir el token Bearer local):

```json
{"action":"create","name":"Diagnóstico diario","task_type":"runtime_diagnostics","params":{},"interval_seconds":86400}
```

Ejemplo de tarea única inmediata: `{"action":"create","name":"Inventario Wi-Fi","task_type":"wifi_inventory","params":{}}`.
Para ejecutar manualmente una tarea existente: `{"action":"run","task_id":"ID"}`.

R2SU no ejecuta comandos shell arbitrarios, código Python enviado por la API, plugins ni herramientas ofensivas. Los intervalos admitidos van de 60 segundos a 30 días; máximo 100 tareas y 500 ejecuciones conservadas. Pausar o detener el programador no borra los datos. La ejecución programada depende de que el puente Termux esté activo; las tareas vencidas se procesan al volver a iniciar el puente.

Pruebas: `python -m unittest tests.test_r2su -v` (o la suite completa con `python -m unittest discover -s tests -v`).


## Diagnóstico del controlador Wi-Fi Android

El núcleo Python incluye \`nexus_android_wifi_diagnostics.py\`, un diagnóstico autenticado y de solo lectura del hardware Wi-Fi visible desde Termux. El endpoint \`GET /api/wifi/diagnostics\` informa:

- Modelo, versión Android, plataforma/board y kernel cuando \`getprop\` los expone.
- Interfaces \`wlan0\`/\`wifi0\`, estado de enlace, ruta de dispositivo, enlace del driver/módulo e IDs vendor/device si sysfs/uevent los publica.
- Estado observable del servicio Wi-Fi Android y permisos de ubicación/dispositivos cercanos que \`dumpsys package\` permita consultar.
- Disponibilidad y resultado de \`termux-wifi-scaninfo\` y \`termux-wifi-connectioninfo\`, con errores/tiempos de espera y número de redes, sin incluir SSID, BSSID ni direcciones IP.
- Hallazgos diferenciados: interfaz ausente, driver no identificable, Wi-Fi desactivado, permisos no confirmados, API ausente/error o resultados Android vacíos. Un escaneo vacío no se etiqueta como fallo del controlador.

También se puede programar en R2SU como \`task_type: wifi_driver_diagnostics\`. La tarea no instala drivers, no altera firmware/kernel ni cambia el estado de radio. Android puede restringir sysfs, \`dumpsys\` y los permisos visibles; en ese caso el informe marca el dato como no confirmado en vez de inventarlo.

Ejecución manual local (con el token Bearer): \`GET http://127.0.0.1:8766/api/wifi/diagnostics\`.
