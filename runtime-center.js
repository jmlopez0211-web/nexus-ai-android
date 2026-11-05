/* NEXUS Runtime Center — additive UI; existing application handlers remain untouched. */
(()=>{
 "use strict";
 const $=id=>document.getElementById(id);
 const status=$("nexus-runtime-status"),summary=$("nexus-runtime-summary");
 const runtimeRoot=$("nexus-runtime-list"),sqlRoot=$("nexus-sql-list");
 const internalRoot=$("nexus-internal-list"),toolsRoot=$("nexus-tools-list");
 const packageRoot=$("nexus-python-packages"),pluginRoot=$("nexus-runtime-plugins"),prootRoot=$("nexus-proot-list"),results=$("nexus-runtime-results");
 let latest=null;
 const token=()=>typeof getBridgeToken==="function"?getBridgeToken():"";
 const base=()=>typeof getWifiBridgeUrl==="function"?getWifiBridgeUrl():"http://127.0.0.1:8766";
 async function request(path,body,timeout=20000){
  const auth=token();if(!auth)throw new Error("Introduce y guarda el token del puente local en Centro Wi-Fi.");
  const options={method:body?"POST":"GET",cache:"no-store",headers:{Authorization:"Bearer "+auth}};
  if(body){options.headers["Content-Type"]="application/json";options.body=JSON.stringify(body);}
  const response=await fetch(base()+path,{...options,signal:AbortSignal.timeout(timeout)});
  const data=await response.json().catch(()=>({error:"Respuesta no válida"}));
  if(!response.ok){
   if(response.status===404&&["/api/engines","/api/diagnostics","/api/engines/run","/api/maintenance/repair","/api/maintenance/repair-dependencies"].includes(path))
    throw new Error("El puente local todavía usa una versión anterior. Hay que actualizar nexus_bridge_termux.py y nexus_runtime_inventory.py una vez y reiniciar el puente; después podrás gestionar estas funciones desde NEXUS.");
   throw new Error(data.error||("HTTP "+response.status));
  }
  return data;
 }
 function card(title,detail,extra){
  const el=document.createElement("article");el.className="finding";
  const h=document.createElement("h4");h.textContent=title;el.append(h);
  if(detail){const p=document.createElement("p");p.textContent=detail;el.append(p);}
  if(extra)el.append(extra);return el;
 }
 function line(root,title,detail){root.append(card(title,detail));}
 function actionButton(label,handler){
  const b=document.createElement("button");b.type="button";b.textContent=label;b.addEventListener("click",handler);return b;
 }
 function renderInventory(data){
  latest=data;
  [runtimeRoot,sqlRoot,internalRoot,toolsRoot,packageRoot,pluginRoot,prootRoot].forEach(x=>x.replaceChildren());
  const device=data.device||{};
  summary.replaceChildren(card("Dispositivo: "+(device.machine||"N/D")+" · Python "+(device.python||"N/D"),
    (device.system||"Android/entorno no identificado")+" · "+(device.architecture||"")+" · Intérprete: "+(device.python_executable||"N/D")));
  (data.runtimes||[]).forEach(item=>{
   const detail=(item.installed?"Instalado":"No instalado")+" · "+(item.version||"versión no disponible")+" · "+(item.path||"");
   const b=actionButton("Probar motor",async()=>{
    b.disabled=true;b.textContent="Probando…";
    try{const out=await request("/api/engines/run",{runtime_id:item.id,confirmed:true});results.prepend(card(item.name+" · "+(out.ok?"PRUEBA CORRECTA":"NO DISPONIBLE"),out.output||out.result||out.note||out.error||out.status));}
    catch(e){results.prepend(card(item.name+" · Error",e.message));}
    finally{b.disabled=false;b.textContent="Probar motor";}
   });
   b.disabled=!item.installed||!["python","node","bash","php","java","ruby","perl","lua","r","go","rust","c-compiler","git"].includes(item.id);
   runtimeRoot.append(card(item.name,detail,b));
  });
  (data.sql_engines||[]).forEach(item=>{
   const b=actionButton(item.id==="postgresql"?"Estado de conexión":"Probar consulta SELECT 1",async()=>{
    b.disabled=true;b.textContent="Comprobando…";
    try{const out=await request("/api/engines/run",{runtime_id:item.id,confirmed:true});results.prepend(card(item.name+" · "+(out.ok?"Correcto":"No disponible"),out.result||out.note||out.error||out.status));}
    catch(e){results.prepend(card(item.name,e.message));}
    finally{b.disabled=false;b.textContent=item.id==="postgresql"?"Estado de conexión":"Probar consulta SELECT 1";}
   });
   b.disabled=!item.installed;
   sqlRoot.append(card(item.name,(item.installed?"Disponible":"No instalado")+" · "+(item.version||item.kind||"")+" · "+item.purpose,b));
  });
  (data.internal_modules||[]).forEach(item=>line(internalRoot,item.name+" · "+item.status,item.path));
  (data.tools||[]).forEach(item=>line(toolsRoot,item.name+" · "+(item.installed?"Instalada":"No detectada"),(item.version||"Versión no disponible")+" · "+item.purpose));
  const packages=data.python_packages||[];
  const packageReport=document.createElement("pre");packageReport.className="finding";
  packageReport.style.whiteSpace="pre-wrap";packageReport.textContent=packages.length+" distribuciones Python instaladas\n"+packages.map(item=>item.name+" "+item.version).join("\n");
  packageRoot.append(packageReport);
  Object.entries(data.python_modules||{}).forEach(([name,installed])=>line(packageRoot,name,installed?"Módulo importable":"No detectado"));
  (data.proot_environments||[]).forEach(item=>line(prootRoot,item.name+" · "+(item.installed?"instalado":"no disponible"),item.python_found?"Python encontrado: "+item.python_path_in_rootfs+" · ejecución todavía no verificada": "No se encontró Python en las rutas habituales"));
  if(!(data.proot_environments||[]).length)line(prootRoot,"No se detectaron distros Proot instaladas","Se ha consultado el directorio de instalación habitual de proot-distro.");
  const plugins=data.plugins||{};
  (plugins.items||[]).forEach(item=>line(pluginRoot,item.name+" · "+(item.approved?"aprobado":"pendiente de aprobación"),item.entrypoint));
  if(!(plugins.items||[]).length)line(pluginRoot,"Sin plugins registrados",plugins.registry_path||"El registro se consulta en Termux.");
  $("nexus-runtime-export").disabled=false;
  status.textContent="Inventario completado. Se muestran únicamente componentes detectados en el entorno del puente local.";
 }
 async function inventory(){
  status.textContent="Consultando motores, módulos, herramientas y SQL…";
  try{const data=await request("/api/engines");if(data.ok!==true)throw new Error("Inventario no válido");renderInventory(data);}
  catch(e){status.textContent="No se pudo consultar el inventario: "+e.message;}
 }
 async function diagnostics(){
  status.textContent="Ejecutando pruebas de diagnóstico de solo lectura…";results.replaceChildren();
  try{
   const data=await request("/api/diagnostics");
   const s=data.summary||{};
   results.append(card("Diagnóstico: "+(data.ok?"sin errores detectados":"requiere revisión"),
    (s.passed||0)+" correctas · "+(s.failed||0)+" fallidas · "+(s.total||0)+" pruebas"));
   (data.checks||[]).forEach(x=>results.append(card((x.ok?"✓ ":"✕ ")+x.name,x.detail)));
   status.textContent="Diagnóstico terminado. No se han modificado archivos del proyecto.";
   latest={...(latest||{}),diagnostics:data};
  }catch(e){status.textContent="Error de diagnóstico: "+e.message;}
 }
 async function repair(){
  if(!window.confirm("NEXUS preparará únicamente sus carpetas privadas de datos y caché. No instalará paquetes ni modificará código o Android. ¿Continuar?"))return;
  status.textContent="Reparando almacenamiento propio de NEXUS…";
  try{
   const data=await request("/api/maintenance/repair",{confirmed:true});
   results.prepend(card("Reparación "+(data.ok?"completada":"parcial"),data.note));
   (data.repaired||[]).forEach(x=>results.prepend(card("✓ "+x.status,x.path)));
   (data.errors||[]).forEach(x=>results.prepend(card("✕ Error",x.path+" · "+x.error)));
   status.textContent=data.ok?"Reparación segura completada.":"Reparación parcial; consulta los errores.";
   latest={...(latest||{}),repair:data};
  }catch(e){status.textContent="No se pudo completar la reparación: "+e.message;}
 }

 async function repairDependencies(){
  if(!window.confirm("NEXUS comprobará sus dependencias principales e instalará únicamente las que falten en el Python del puente local. No solicitará actualizar paquetes principales ya presentes; pip podría ajustar dependencias transitivas si fuera necesario. ¿Continuar?"))return;
  status.textContent="Comprobando e instalando, si hace falta, las dependencias ausentes…";
  try{
   const data=await request("/api/maintenance/repair-dependencies",{confirmed:true},200000);
   results.prepend(card("Reparación de dependencias "+(data.ok?"correcta":"incompleta"),data.note));
   (data.installed||[]).forEach(name=>results.prepend(card("✓ Dependencia disponible",name)));
   (data.unresolved||[]).forEach(name=>results.prepend(card("✕ Dependencia pendiente",name)));
   if(data.output)results.prepend(card("Salida de pip",data.output));
   status.textContent=data.ok?"Dependencias comprobadas.":"La reparación no se completó por completo; consulta el resultado.";
   latest={...(latest||{}),dependency_repair:data};
  }catch(e){status.textContent="No se pudieron reparar las dependencias: "+e.message;}
 }
 $("nexus-runtime-inventory").addEventListener("click",inventory);
 $("nexus-runtime-diagnostics").addEventListener("click",diagnostics);
 $("nexus-runtime-repair").addEventListener("click",repair);
 $("nexus-dependency-repair").addEventListener("click",repairDependencies);
 $("nexus-runtime-export").addEventListener("click",()=>{
  if(!latest)return;
  const blob=new Blob([JSON.stringify(latest,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download="nexus-runtime-diagnostic.json";a.click();URL.revokeObjectURL(url);
 });
})();
