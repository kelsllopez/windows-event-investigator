# 🪟 Windows Event Investigator — SOC Toolkit

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)
![Windows](https://img.shields.io/badge/Windows_Server-2019%2F2022-blue?style=flat-square&logo=windows)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

Script PowerShell para análisis forense de Event IDs críticos de Windows. Detecta brute force, escalada de privilegios, servicios maliciosos y persistencia. Genera reporte HTML visual + JSON para integración con SIEM (Wazuh).

---

## 🔍 ¿Qué detecta?

```
Windows Event Log
       │
       ├── Brute Force ──────── 5+ EventID 4625 en 5 min desde misma IP
       │
       ├── Privilege Escalation  EventID 4728 → Domain Admins
       │                         EventID 4732 → Administradores locales
       │                         EventID 4720 → Cuenta nueva creada
       │
       ├── Persistence ──────── EventID 7045 → Servicio sospechoso
       │                         EventID 4698 → Tarea programada
       │                         EventID 4657 → Registro Run modificado
       │
       └── Defense Evasion ──── EventID 1102 → Log limpiado
```

---

## 🚀 Uso

```powershell
# Requiere PowerShell como Administrador

# Análisis estándar (últimas 24 horas)
.\Invoke-EventInvestigator.ps1

# Últimas 72 horas
.\Invoke-EventInvestigator.ps1 -HoursBack 72

# Guardar reportes en carpeta específica
.\Invoke-EventInvestigator.ps1 -OutputPath "C:\SOC\Reports"

# Solo JSON (para automatización / SIEM)
.\Invoke-EventInvestigator.ps1 -ExportHTML $false

# Solo HTML (para presentación)
.\Invoke-EventInvestigator.ps1 -ExportJSON $false
```

---

## 📊 Output de ejemplo

```
  ╔══════════════════════════════════════════════════════╗
  ║     WINDOWS EVENT INVESTIGATOR — SOC Toolkit         ║
  ║     CyberCorp S.A. | Blue Team                       ║
  ╚══════════════════════════════════════════════════════╝

  [*] Recopilando eventos de las últimas 24 horas...
  [+] Total eventos encontrados: 847

  Event IDs detectados:
    🔴  EventID 4625 | Login Fallido           | Count: 47  | T1110
    🔵  EventID 4624 | Login Exitoso           | Count: 125 | T1078
    🔴  EventID 4720 | Cuenta Nueva Creada     | Count: 1   | T1136
    🔴  EventID 4728 | Usuario → Domain Admins | Count: 1   | T1098
    🟠  EventID 7045 | Nuevo Servicio Instalado| Count: 1   | T1543.003

  🚨 ALERTAS CRÍTICAS DETECTADAS: 3

    🔴 BRUTE FORCE    | IP: 192.168.56.30 | Intentos: 47 | T1110.001
    🔴 ESCALADA PRIVS | Administrador agregó hackersoc a Domain Admins | T1098
    🟠 SERV. SOSPECHOSO | WindowsUpdateHelper | Ejecutable .ps1 en ruta no estándar

  [+] Reporte HTML guardado: reports\EventReport_2026-06-17_21-00-00.html
  [+] Reporte JSON guardado: reports\EventReport_2026-06-17_21-00-00.json
```

---

## 📋 Event IDs monitoreados

| Event ID | Descripción | Categoría | Severidad | MITRE |
|---|---|---|---|---|
| 4625 | Login Fallido | Credential Access | 🟠 Medium | T1110 |
| 4624 | Login Exitoso | Authentication | 🔵 Info | T1078 |
| 4648 | Login con credenciales explícitas | Credential Access | 🟠 High | T1078 |
| 4720 | Cuenta nueva creada | Privilege Escalation | 🟠 High | T1136 |
| 4722 | Cuenta habilitada | Account Management | 🟡 Medium | T1098 |
| 4726 | Cuenta eliminada | Account Management | 🟡 Medium | T1531 |
| 4740 | Cuenta bloqueada | Credential Access | 🟠 High | T1110 |
| **4728** | **Usuario → Domain Admins** | **Privilege Escalation** | **🔴 Critical** | **T1098** |
| **4732** | **Usuario → Administradores** | **Privilege Escalation** | **🔴 Critical** | **T1098** |
| 4672 | Privilegios especiales asignados | Privilege Escalation | 🟠 High | T1484 |
| 4688 | Proceso nuevo creado | Execution | 🟡 Medium | T1059 |
| **7045** | **Nuevo servicio instalado** | **Persistence** | **🟠 High** | **T1543.003** |
| **4698** | **Tarea programada creada** | **Persistence** | **🟠 High** | **T1053.005** |
| 4657 | Valor de registro modificado | Persistence | 🟠 High | T1547.001 |
| **1102** | **Log de auditoría limpiado** | **Defense Evasion** | **🔴 Critical** | **T1070.001** |

---

## 📁 Estructura del proyecto

```
windows-event-investigator/
├── Invoke-EventInvestigator.ps1   # Script principal
├── samples/
│   ├── sample_events.json         # Eventos de ejemplo para demo
│   └── expected_output.txt        # Output esperado
├── reports/                       # Reportes generados (auto)
│   ├── EventReport_FECHA.html     # Reporte visual
│   └── EventReport_FECHA.json     # Para SIEM/Wazuh
└── README.md
```

---

## 🔧 Detección de servicios sospechosos

El script marca un servicio como sospechoso si cumple alguno de estos criterios:

```powershell
# Ejecutable con extensión sospechosa
$imagePath -like "*.ps1*"   # PowerShell script
$imagePath -like "*.bat*"   # Batch file
$imagePath -like "*.vbs*"   # VBScript

# Ruta no estándar
$imagePath -like "*\temp\*"     # Carpeta temporal
$imagePath -like "*\appdata\*"  # Perfil de usuario
$imagePath -like "*\users\*"    # Directorio de usuarios

# Nombre que imita Windows
"windowsupdate", "windowssecurity", "svchost32"...

# LocalSystem + ejecutable no estándar
$account -eq "LocalSystem" -and $imagePath -notlike "*system32\svchost*"
```

---

## 🔗 Conexión con Wazuh

El JSON generado puede ingestarse en Wazuh para correlación:

```bash
# En Ubuntu (Wazuh Manager)
# Configurar filebeat para leer los reportes JSON
# o usar la API de Wazuh para importar eventos
```

---

## ⚙️ Requisitos

- Windows 10/11 o Windows Server 2016+
- PowerShell 5.1 o superior
- Ejecutar como **Administrador** (necesario para leer Security Event Log)
- Auditoría de eventos habilitada en Windows

### Habilitar auditoría (si no está activa)

```powershell
# Habilitar auditoría de logon events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Habilitar auditoría de gestión de cuentas
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Habilitar auditoría de servicios
auditpol /set /subcategory:"Security System Extension" /success:enable
```

---

## 👩‍💻 Sobre este proyecto

Desarrollado con experiencia real en entornos Windows Server 2022 + Active Directory (soporte N1/N2, +80 usuarios, Portuaria Corral S.A.). Los Event IDs monitoreados son exactamente los que aparecieron durante la semana de simulación SOC en CyberCorp S.A.

📧 kels.sepulvedaa@gmail.com | 📍 Valdivia/Temuco, Chile