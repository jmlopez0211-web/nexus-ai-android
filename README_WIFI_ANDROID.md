# NEXUS IA — conexión Wi-Fi local con Termux

Esta guía corresponde al puente actual del repositorio: `nexus_bridge_termux.py`, puerto `8766`. No uses el puente heredado `nexus_wifi_bridge.py` ni el puerto antiguo `8765` para esta versión de NEXUS.

## Requisitos

- Termux y Termux:API instalados desde fuentes compatibles.
- Python y el paquete cliente Termux:API:
  ```bash
  pkg install python termux-api
  ```
- Permisos de Android para Termux:API y ubicación/Wi-Fi cuando Android los solicite.

## Arranque y autenticación

Desde la carpeta del repositorio en Termux:

```bash
cd ~/nexus-ai-android
python nexus_bridge_termux.py
```

El servidor escucha solo en `127.0.0.1:8766`. Si aparece `Address already in use`, no inicies otra instancia: comprueba la instancia existente con:

```curl -i --max-time 3 http://127.0.0.1:8766/api/status```

Un `401 Unauthorized` sin encabezado Authorization confirma que el servidor responde y exige autenticación; no indica que esté caído.

El token persistente se lee de `~/.nexus_bridge_token`. No se muestra ni se debe publicar. Para copiarlo directamente al portapapeles de Termux sin imprimirlo:

```bash
termux-clipboard-set "$(cat ~/.nexus_bridge_token)"
```

En NEXUS IA abre **Centro de auditoría Wi-Fi**, conserva la dirección `http://127.0.0.1:8766`, pega el token y pulsa **Guardar dirección**. El panel guarda las credenciales localmente antes de comprobar la conexión. No pulses «Olvidar token» salvo que quieras eliminarlo del navegador.

## Diagnóstico

Consulta autenticada desde Termux:

```bash
curl -i -H "Authorization: Bearer $(cat ~/.nexus_bridge_token)" \
  http://127.0.0.1:8766/api/status
```

La respuesta esperada es `HTTP 200` con `"ok": true`. La prueba CORS previa desde el origen Render debe responder `204` e incluir `Access-Control-Allow-Origin`, `Access-Control-Allow-Headers: Authorization, Content-Type` y `Access-Control-Allow-Private-Network: true`.

## Seguridad y límites

- El servidor escucha exclusivamente en loopback. No cambies HOST a `0.0.0.0`, no reenvíes el puerto y no lo publiques en Internet.
- El token se envía solo al puente local mediante `Authorization: Bearer`; no lo incluyas en capturas, informes ni repositorios.
- El inventario Wi-Fi depende de Termux:API, permisos de Android y las restricciones de escaneo del fabricante. La caché puede mostrar la última lectura válida si Android limita una consulta nueva.
- El escaneo TCP se limita a una única IPv4 privada y requiere confirmación de autorización. No recorre subredes, no prueba contraseñas ni identifica versiones o vulnerabilidades.
- Los módulos de herramientas inalámbricas se diagnostican en modo de solo lectura; no se ejecutan herramientas de captura, suplantación ni recuperación de claves.

## Lectura Wi-Fi: qué significa "en directo"

`termux-wifi-scaninfo` devuelve la lista de resultados que Android tiene disponibles en ese momento. El comando de Termux:API lee `WifiManager.getScanResults()`; no solicita por sí solo un escaneo físico nuevo. Android puede devolver resultados de una exploración anterior y también limita la frecuencia de los escaneos.

NEXUS conserva dos marcas distintas:

- `cache_age_seconds`: cuánto tiempo hace que el puente guardó una respuesta no vacía.
- `scan_age_seconds`: antigüedad estimada a partir de `ScanResult.timestamp` de Android, cuando el dato está disponible.

Por eso, `mode=live` significa que esta consulta de Termux:API devolvió redes; no significa necesariamente que la radio haya iniciado un escaneo nuevo en ese instante. `mode=cached` significa que Android no entregó redes nuevas en esa consulta y el puente conserva el inventario previo dentro del TTL de 15 minutos.

La PWA distingue ahora origen, antigüedad y caché. El JSON exportado conserva esos metadatos y ya no etiqueta automáticamente toda exportación como `live`.

## Comprobaciones de reparación

Desde la raíz del repositorio:

```bash
python -m unittest discover -s tests -v
python -m py_compile main.py app.py audit_engine.py nexus_bridge_termux.py nexus_wireless_engine.py nexus_plugin_manager.py nexus_wifi_bridge.py
```

En Android, mantén el puente limitado a `127.0.0.1`. La respuesta esperada de `/api/wifi` incluye `mode`, `cached`, `source`, `requested_at`, `cache_age_seconds` y, cuando Android expone la marca temporal, `scan_age_seconds`.


## Diagnóstico de hardware, permisos y capacidades

La ruta autenticada `GET /api/capabilities` devuelve el diagnóstico separado de Termux/Android y Ubuntu Proot. Se consulta con el mismo token privado del puente:

```bash
curl -sS -H "Authorization: Bearer $(cat ~/.nexus_bridge_token)" \
  http://127.0.0.1:8766/api/capabilities | python -m json.tool
```

El informe separa instalación (`installed`), permiso de ejecución (`executable_permission`) y respuesta a una comprobación inocua de ayuda/versión (`execution_probe`). Informa UID, UID efectivo, grupos y bits CapEff; el UID 0 de Ubuntu Proot nunca se interpreta como root Android.

Las consultas `iw dev` y `iw list` son de lectura. Si el controlador anuncia `monitor`, el resultado queda como `advertised_not_functionally_verified`: no se crea ni activa una interfaz. La inyección de paquetes se deja en `unknown`, porque una consulta pasiva no puede demostrarla y este diagnóstico no transmite tramas de prueba. No cambia interfaces, eleva privilegios ni captura credenciales.

La comprobación de `termux-wifi-scaninfo` solo informa el número de resultados y omite SSID/BSSID del informe de capacidades.
