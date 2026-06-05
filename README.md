# Ataque-STP-Root-Attack

<img width="654" height="276" alt="image" src="https://github.com/user-attachments/assets/edfcc30b-66cc-4465-95dc-13ea7e5fda80" />

**LABORATORIO DE SEGURIDAD DE REDES**

**STP ROOT ATTACK**

_Documentación Técnica Profesional_

**Estudiante:**

**Heldry Terrero**

Matrícula: 2025-0719

Materia: Seguridad de Redes

Fecha: Junio 2026

  
  

# Aviso de Uso Responsable

|   |
|---|
|**⚠  AVISO IMPORTANTE — LEA ANTES DE UTILIZAR ESTE MATERIAL**<br><br>Este proyecto fue desarrollado únicamente con fines educativos, académicos<br><br>y de laboratorio controlado, en el marco de la asignatura Seguridad de Redes.<br><br>Los scripts, comandos y técnicas incluidos en este repositorio deben ejecutarse<br><br>SOLAMENTE en entornos propios o autorizados, tales como:<br><br>   • Simuladores: PNetLab, GNS3, EVE-NG<br><br>   • Laboratorios internos de práctica académica<br><br>   • Redes virtuales de prueba bajo supervisión docente<br><br>QUEDA ESTRICTAMENTE PROHIBIDO:<br><br>   • Utilizar este material en redes públicas, corporativas o de terceros<br><br>     sin autorización explícita y por escrito.<br><br>   • Interceptar, alterar o interrumpir comunicaciones ajenas.<br><br>   • Aplicar estas técnicas con fines maliciosos o fraudulentos.<br><br>El uso indebido de estas herramientas puede constituir un delito tipificado<br><br>en las leyes de ciberseguridad y delitos informáticos vigentes.<br><br>El autor de este material no se hace responsable del uso indebido del mismo.|

# Documentación Técnica — Ataque STP Root Claim

|**Campo**|**Valor**|
|---|---|
|Estudiante|Heldry Terrero|
|Matrícula|2025-0719|
|Materia|Seguridad de Redes|
|Script|stp_root_attack.py|
|Fecha|Junio 2026|
|Plataforma|PNetLab — Kali Linux|

# 1. Objetivo del Laboratorio

Demostrar cómo el protocolo STP (Spanning Tree Protocol) puede ser manipulado para que el equipo del atacante sea elegido como Root Bridge, forzando la reconvergencia de la red y redirigiendo todo el tráfico por el atacante.

# 2. Objetivo del Script

Enviar BPDUs de configuración STP con prioridad 0 (la más alta posible) para ganar la elección de Root Bridge, complementado con BPDUs TCN para forzar el vaciado de las tablas CAM de todos los switches y el modo continuo para mantenerse como Root Bridge.

# 3. Requisitos

## 3.1 Software

•        Python 3.7 o superior

•        Scapy 2.4.3: sudo apt install python3-scapy

•        Kali Linux con interfaz eth1 conectada al switch

•        Privilegios de root (sudo)

## 3.2 Red

•        Atacante: 20.25.7.100/24 en eth1

•        Víctima: 20.25.7.10/24

•        Gateway/Router: 20.25.7.1/24

•        Red: 20.25.7.0/24

# 4. Parámetros del Script

|**Parámetro**|**Descripción**|**Default**|
|---|---|---|
|-i / --iface|Interfaz de red|Requerido|
|-p / --priority|Prioridad STP del atacante (0=máxima)|0|
|--interval|Intervalo entre BPDUs en segundos|2.0|
|--tcn|Enviar TCN BPDUs (vaciar tablas CAM)|False|
|--continuous|Mantener posición de Root Bridge|False|
|--scout|Escuchar BPDUs antes de atacar|False|

# 5. Cómo se Ejecutó el Script

**Comando utilizado durante la demostración:**

sudo python3 stp_root_attack.py -i eth1 -p 0 --continuous --tcn --scout

|   |
|---|
|**Resultado esperado en pantalla**<br><br>[SCOUT] Escuchando BPDUs actuales (10 seg)...<br><br>[BPDU] Root actual -> Priority: 32769 \| MAC: aa:bb:cc:00:02:00<br><br>[*] Nuestro ataque usara Priority=0 (menor que 32769) -> ganaremos<br><br>[*] Fase 1 — Rafaga inicial de 30 BPDUs...<br><br>[+] Rafaga completada: 30 BPDUs enviados<br><br>[+] Fase 2 — Enviando TCN BPDUs...<br><br>[+] Manteniendo Root Bridge (cada 2s)...|

# 6. Funcionamiento del Ataque

En STP, el Root Bridge se elige comparando el Bridge ID (prioridad de 2 bytes + MAC de 6 bytes). El Bridge ID menor gana. El switch tiene prioridad 32769, por lo que enviando BPDUs con prioridad 0, el atacante siempre gana. Una vez elegido Root Bridge, todos los switches recalculan sus puertos bloqueados/designados, y el tráfico fluye a través del atacante.

•        Paso 1: (Scout) Se escuchan BPDUs existentes para conocer el Root Bridge actual y su prioridad.

•        Paso 2: Se construye un BPDU de configuración con: priority=0, root_path_cost=0, flags=TC.

•        Paso 3: Se envía una ráfaga inicial de 30 BPDUs para ganar la elección rápidamente.

•        Paso 4: Se envían 10 TCN BPDUs para forzar el vaciado de tablas CAM en todos los switches.

•        Paso 5: En modo continuo: se reenvía un BPDU cada 2 segundos (equivalente al hello timer STP).

•        Paso 6: Los switches actualizan su topología y redirigen tráfico por el 'nuevo Root Bridge'.

# 7. Verificación del Ataque

**Para confirmar que el ataque fue exitoso, se ejecutaron los siguientes comandos:**

Switch# show spanning-tree

Verificar: Root ID Priority = 1 o 0

Verificar: Root ID Address = MAC del atacante (50:f0:0a:00:04:00)

Switch# show spanning-tree detail

|   |
|---|
|**¿Qué se debe observar?**<br><br>Root ID Priority cambia de 32769 a 1 (0 + sys-id-ext 1).<br><br>Root ID Address cambia de aabb.cc00.0200 a la MAC del atacante.<br><br>Los puertos pueden cambiar de estado (FWD/BLK) durante la reconvergencia.<br><br>'This bridge is the root' desaparece del switch legítimo.|

# 8. Contramedidas

BPDU Guard deshabilita automáticamente cualquier puerto que reciba un BPDU inesperado (puertos de usuario no deberían recibir BPDUs). Root Guard evita que un puerto se convierta en Root Port, protegiendo la posición del Root Bridge actual.

Switch(config)# spanning-tree portfast bpduguard default

Switch(config-if)# spanning-tree portfast

Switch(config-if)# spanning-tree bpduguard enable

Switch(config-if)# spanning-tree guard root

Switch# show spanning-tree inconsistentports

# 9. Conclusión

El ataque STP Root Claim demuestra que los protocolos de control de infraestructura como STP fueron diseñados sin contemplar la presencia de actores maliciosos en la red. BPDU Guard y Root Guard son las contramedidas estándar y deben configurarse en todos los puertos de acceso de usuario en redes de producción.  
  
Link de GitHub: https://github.com/HeldryRoot/Ataque-STP-Root-Attack

Link del Video de Youtube: https://youtu.be/76jJZCWF9IU?si=MpYJM7LkR3Uwq7xx

**Heldry Terrero — Matrícula 2025-0719 — Seguridad de Redes — Junio 2026**
