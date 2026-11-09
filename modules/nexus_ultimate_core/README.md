# NEXUS IA — UltimateCore (Termux / Android ARM64)

Módulo independiente para añadir a NEXUS sin sustituir el puente existente ni la interfaz web.

## Contenido

- `ultimate_core.py`: clase `UltimateCore`, con alias compatible `NexusCore`.
- `config.json`: configuración editable de timeout, logs, carpetas y ruta de Nmap.
- `tests/test_ultimate_core.py`: pruebas automáticas.
- `reports/`: informes JSON generados.
- `logs/`: registro local del motor.

## Instalación en Termux

En Termux (no dentro de Ubuntu Proot):

```bash
pkg update
pkg install -y python nmap termux-api
```

La app Termux:API debe estar instalada desde la misma fuente/firma que Termux y tener permisos Android.

## Ejecutar desde este directorio

Diagnóstico:

```bash
python ultimate_core.py --module system_check
```

Batería:

```bash
python ultimate_core.py --module termux_api --action battery
```

Conexión Wi-Fi:

```bash
python ultimate_core.py --module termux_api --action wifi_connection
```

Resultados Wi-Fi actuales disponibles en Android:

```bash
python ultimate_core.py --module termux_api --action wifi_scan
```

Escaneo TCP connect del propio teléfono:

```bash
python ultimate_core.py --module nmap --target 127.0.0.1 --yes-authorized
```

Escaneo de un único host privado de laboratorio que administras:

```bash
python ultimate_core.py --module nmap --target 192.168.1.10 --yes-authorized
```

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Integración en NEXUS

El módulo está separado para validar su ejecución antes de conectarlo al endpoint de lanzamiento. La integración debe registrar un módulo fijo y pasar argumentos explícitos; no debe aceptar una cadena de shell arbitraria desde JavaScript.

## Límites técnicos

- Nmap usa TCP connect (`-sT`) y no necesita root Android para ese modo.
- El objetivo se limita a una IP IPv4 privada o loopback, con confirmación explícita.
- Termux:API Wi-Fi consulta los resultados que Android tiene disponibles; no garantiza que fuerce un nuevo escaneo físico.
- Ubuntu Proot no concede root Android ni habilita automáticamente modo monitor o inyección Wi-Fi.
- Un puerto abierto es una observación, no una confirmación automática de vulnerabilidad.
- Nunca se incluyen tokens o claves API en los informes.
