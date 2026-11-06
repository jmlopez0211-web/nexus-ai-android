/* NEXUS IA — recuperación guiada de routers. No solicita ni almacena contraseñas. */
(function () {
  "use strict";
  const $ = id => document.getElementById(id);
  let latestReport = null;

  const PROVIDER_NOTES = {
    "Movistar": "Consulta la app o el área privada de Movistar y la documentación del modelo HGU. Si el acceso de administración está disponible, revisa allí la configuración Wi-Fi.",
    "O2": "Consulta la app o el área de cliente de O2 y sus canales de soporte para el router suministrado.",
    "Orange": "Consulta Mi Orange y la documentación del router entregado por Orange; confirma con soporte antes de restablecerlo.",
    "Jazztel": "Consulta el área de cliente y el soporte de Jazztel para identificar el modelo y recuperar o reconfigurar el Wi-Fi.",
    "Vodafone": "Consulta Mi Vodafone y el soporte técnico para identificar el modelo y el procedimiento oficial.",
    "Lowi": "Consulta el área de cliente o soporte de Lowi; confirma si el router recupera automáticamente la configuración del operador.",
    "Digi": "Consulta Mi DIGI y el soporte técnico para identificar el router y confirmar los pasos de recuperación.",
    "MásMóvil": "Consulta el área de cliente y soporte de MásMóvil; confirma el modelo y la configuración de fibra antes de restablecer.",
    "Yoigo": "Consulta el área de cliente y soporte de Yoigo; confirma el modelo y el procedimiento oficial.",
    "Otro / desconocido": "Identifica primero el operador en la factura, contrato o etiqueta del equipo y consulta su soporte oficial."
  };

  function addStep(list, title, detail, caution) {
    list.push({title, detail, caution: caution || "", status: "pendiente"});
  }

  function buildGuide() {
    const provider = $("router-provider").value;
    const brand = $("router-brand").value;
    const model = $("router-model").value.trim();
    const situation = $("router-access-state").value;
    if (!$("router-owner-confirmed").checked) {
      $("router-recovery-status").textContent = "Confirma que eres titular o tienes autorización expresa antes de continuar.";
      return;
    }
    const steps = [];
    addStep(steps, "Identificar el equipo", "Fotografía la etiqueta inferior o trasera y anota fabricante, modelo y número de serie. No publiques la etiqueta ni compartas el número de serie en el informe.");
    addStep(steps, "Comprobar la etiqueta Wi-Fi", "Busca los campos SSID, WLAN Key, Wi-Fi Key o contraseña inalámbrica. Si la clave original no se ha cambiado, puede seguir siendo válida.", "No confundas la clave Wi-Fi con la contraseña de administración.");
    addStep(steps, "Consultar al operador", PROVIDER_NOTES[provider] || "Consulta el soporte oficial del operador que suministró el equipo.");
    if (situation === "admin_access") {
      addStep(steps, "Usar el panel de administración", "Accede solo con las credenciales de administración legítimas que ya tengas. Localiza Wi-Fi / WLAN y cambia la clave por una nueva, larga y única. Guarda los cambios y vuelve a conectar los dispositivos.");
    } else if (situation === "provider_access") {
      addStep(steps, "Usar la aplicación o área de cliente", "Comprueba si el operador permite consultar o cambiar el nombre y la contraseña Wi-Fi desde su aplicación o portal autenticado. Sigue únicamente el procedimiento oficial.");
    } else {
      addStep(steps, "Recuperar acceso sin dispositivos conectados", "Prueba primero la etiqueta del router y la app o área de cliente del operador. Si el panel de administración sigue accesible desde una conexión Ethernet, utiliza un ordenador conectado por cable y las credenciales administrativas legítimas.");
    }
    addStep(steps, "Restablecimiento de fábrica (último recurso)", "Solo si el titular lo autoriza y el operador confirma que el equipo puede reprovisionarse. Mantén pulsado RESET el tiempo indicado en el manual del modelo; después configura el Wi-Fi de nuevo siguiendo las instrucciones del operador.", "El reset puede borrar SSID, clave, ajustes personalizados, telefonía, IPTV o parámetros de conexión. No lo hagas sin confirmar cómo recuperar la configuración del operador.");
    addStep(steps, "Verificar y cerrar", "Conecta un dispositivo autorizado a la nueva red. Comprueba WPA2-AES o WPA3, desactiva WPS si no es necesario y verifica que la conexión a Internet y los servicios contratados funcionan.");
    const report = {
      application: "NEXUS IA",
      module: "Router access recovery guide",
      generated_at: new Date().toISOString(),
      authorization_confirmed: true,
      provider: provider || "No indicado",
      manufacturer: brand || "No indicado",
      model: model || "No indicado",
      situation,
      credential_handling: {password_requested: false, password_stored: false, password_exported: false, hidden_credentials_extracted: false},
      steps,
      outcome: "Guía generada; recuperación aún no verificada",
      limitations: [
        "La guía no accede al router ni cambia su configuración.",
        "No extrae, descifra ni revela contraseñas guardadas u ocultas.",
        "El restablecimiento de fábrica puede interrumpir servicios y debe confirmarse con el operador.",
        "Los pasos concretos dependen del modelo, firmware y operador."
      ]
    };
    latestReport = report;
    render(report);
    $("router-recovery-status").textContent = "Guía generada. Marca cada paso al completarlo y registra el resultado sin introducir contraseñas.";
    $("router-recovery-export").disabled = false;
    $("router-recovery-print").disabled = false;
  }

  function render(report) {
    const root = $("router-recovery-results");
    root.replaceChildren();
    const summary = document.createElement("div");
    summary.className = "notice";
    summary.textContent = [report.provider, report.manufacturer, report.model].join(" · ") + " — " + report.outcome;
    root.append(summary);
    report.steps.forEach((step, index) => {
      const card = document.createElement("article");
      card.className = "finding info";
      const heading = document.createElement("h4");
      heading.textContent = (index + 1) + ". " + step.title;
      const detail = document.createElement("p");
      detail.textContent = step.detail;
      card.append(heading, detail);
      if (step.caution) {
        const warning = document.createElement("p");
        warning.className = "wifi-warning";
        warning.textContent = "Precaución: " + step.caution;
        card.append(warning);
      }
      const label = document.createElement("label");
      label.style.cssText = "display:flex;gap:10px;align-items:center;margin-top:10px";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = step.status === "completado";
      checkbox.style.width = "auto";
      checkbox.addEventListener("change", () => {
        step.status = checkbox.checked ? "completado" : "pendiente";
        report.outcome = report.steps.every(item => item.status === "completado")
          ? "Pasos marcados como completados; confirmar conexión y servicios"
          : "Recuperación en curso";
        summary.textContent = [report.provider, report.manufacturer, report.model].join(" · ") + " — " + report.outcome;
      });
      const text = document.createElement("span");
      text.textContent = "Paso completado";
      label.append(checkbox, text);
      card.append(label);
      root.append(card);
    });
    const note = document.createElement("p");
    note.className = "muted";
    note.textContent = "El informe no contiene contraseñas, números de serie ni credenciales administrativas.";
    root.append(note);
  }

  function downloadReport() {
    if (!latestReport) return;
    const blob = new Blob([JSON.stringify(latestReport, null, 2)], {type: "application/json"});
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "nexus-recuperacion-router.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function printReport() {
    if (!latestReport) return;
    const escape = value => String(value).replace(/[&<>"']/g, char => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
    const rows = latestReport.steps.map((step, index) =>
      "<li><strong>" + escape(step.title) + "</strong><p>" + escape(step.detail) + "</p>" +
      (step.caution ? "<p><strong>Precaución:</strong> " + escape(step.caution) + "</p>" : "") +
      "<p>Estado: " + escape(step.status) + "</p></li>").join("");
    const win = window.open("", "_blank");
    if (!win) {
      $("router-recovery-status").textContent = "El navegador bloqueó la ventana. Permite ventanas emergentes para imprimir el informe.";
      return;
    }
    win.document.write("<!doctype html><html lang='es'><meta charset='utf-8'><title>Informe NEXUS — recuperación router</title><style>body{font:15px system-ui;max-width:850px;margin:36px auto;padding:0 18px;color:#173247}li{margin:18px 0}p{line-height:1.5}.note{background:#eef8f6;padding:12px}</style><h1>NEXUS IA · Recuperación de router</h1><p>" +
      escape(latestReport.provider) + " · " + escape(latestReport.manufacturer) + " · " + escape(latestReport.model) +
      "</p><p class='note'>No se han solicitado, almacenado ni exportado contraseñas.</p><ol>" + rows +
      "</ol><p>Resultado: " + escape(latestReport.outcome) + "</p></html>");
    win.document.close();
    win.focus();
    win.print();
  }

  function resetGuide() {
    latestReport = null;
    $("router-provider").value = "";
    $("router-brand").value = "";
    $("router-model").value = "";
    $("router-access-state").value = "no_devices";
    $("router-owner-confirmed").checked = false;
    $("router-recovery-results").replaceChildren();
    $("router-recovery-status").textContent = "Formulario reiniciado. No se ha guardado ningún dato.";
    $("router-recovery-export").disabled = true;
    $("router-recovery-print").disabled = true;
  }

  $("router-recovery-guide").addEventListener("click", buildGuide);
  $("router-recovery-reset").addEventListener("click", resetGuide);
  $("router-recovery-export").addEventListener("click", downloadReport);
  $("router-recovery-print").addEventListener("click", printReport);
})();
