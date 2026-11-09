# NEXUS IA — arranque automático y recuperación en Android

## Qué hace

NEXUS usa tres capas:

1. **Termux:Boot** inicia el supervisor al arrancar Android.
2. **Supervisor** ejecuta `nexus_bridge_termux.py` y vuelve a iniciarlo si el proceso termina inesperadamente, con espera progresiva de 3 a 60 segundos.
3. **Comprobación de salud** consulta `/api/status` cada 25 segundos. Si falla tres veces seguidas, finaliza el proceso bloqueado y el supervisor lo reinicia.

El puente continúa escuchando exclusivamente en `127.0.0.1:8766`; no se publica en la LAN ni en Internet. El token existente `~/.nexus_bridge_token` se conserva.

## Requisito Android que no se puede omitir

Android no permite que una PWA cree archivos dentro del espacio privado de Termux ni que inicie Termux si Android no lo ha autorizado. Por eso hace falta una instalación inicial única:

- Instala **Termux:Boot** desde la misma fuente que tu Termux (no mezcles APK de Google Play, F-Droid y GitHub).
- Abre Termux:Boot una vez después de instalarlo.
- Descarga/actualiza los archivos de NEXUS en `~/nexus-ai-android`.
- Ejecuta una sola vez `bash ~/nexus-ai-android/install_termux_autostart.sh` desde Termux.

El instalador copia el lanzador a `~/.termux/boot/`, conserva el token, detiene únicamente una instancia antigua de `nexus_bridge_termux.py` cuyo directorio de trabajo sea el repositorio NEXUS y arranca el supervisor. No modifica módulos originales ni instala herramientas de auditoría.

## Ajustes Samsung / Android

En Ajustes > Aplicaciones, revisa Termux y Termux:Boot y selecciona batería **Sin restricciones** o el ajuste equivalente de tu versión de One UI. Permite que Termux:Boot se ejecute en segundo plano y no incluyas Termux en aplicaciones en suspensión profunda. Los nombres exactos pueden variar con la versión de Android.

El bloqueo de CPU está desactivado por defecto para evitar consumo continuo. Si necesitas máxima continuidad con la pantalla apagada, edita `~/.config/nexus-ai/bridge.conf` y cambia a `KEEP_CPU_AWAKE=1`. Esto usa `termux-wake-lock` si está disponible y aumenta el consumo de batería. No se activa automáticamente.

## Controles desde NEXUS

Con la versión nueva del puente, el Centro de motores muestra si el supervisor está activo y permite **Reiniciar puente automáticamente**. El reinicio solo se habilita cuando el supervisor está detectado; el propio supervisor vuelve a levantar el servidor tras la parada controlada.

Si el supervisor no está activo, la web no puede instalarlo a distancia: hay que completar la instalación única anterior. La PWA muestra el estado de conexión, pero no puede saltarse el aislamiento de Android.

## Registros y control manual

- Registro: `~/.cache/nexus-ai/bridge-supervisor.log` (rotación a 1 MB).
- PID del supervisor: `~/.cache/nexus-ai/bridge-supervisor.pid`.
- PID del puente: `~/.cache/nexus-ai/bridge-child.pid`.
- Parada: `bash ~/nexus-ai-android/nexus_bridge_stop.sh`.
- Arranque manual del supervisor: `bash ~/nexus-ai-android/nexus_bridge_start.sh`.

El script de parada solicita detener el puente y evita que el supervisor lo reinicie hasta el siguiente arranque de Android. El arranque automático de Termux:Boot elimina esa marca en el próximo reinicio del dispositivo.

## Recuperación y límites

El supervisor recupera una caída del proceso y una API que deja de responder. No puede recuperar fallos de Android que cierren Termux/Termux:Boot, falta de batería, revocación de permisos, desinstalación de Termux:API ni ausencia de red/paquetes. En esos casos NEXUS presenta el puente como desconectado y el registro local conserva el motivo cuando el proceso pudo escribirlo.

No se configura un servicio remoto, túnel, puerto público ni ejecución de comandos arbitrarios. Los registros no contienen el token.


## Compatibilidad con el comando de plugin antiguo

Si Termux:Plugin intenta ejecutar `~/nexus-ai-android/nexus_bridge_watchdog.sh`, el repositorio incluye ese punto de entrada compatible. Tras actualizar el repositorio, dale permiso de ejecución una vez con `chmod 700 ~/nexus-ai-android/nexus_bridge_watchdog.sh`. El instalador de arranque automático también aplica ese permiso. El script delega en `nexus_bridge_start.sh`, que inicia el supervisor existente; no crea un segundo servidor ni un watchdog paralelo.
