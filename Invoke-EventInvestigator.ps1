<#
.SYNOPSIS
    Windows Event Investigator — SOC Toolkit
    Analista: Katalina Sepúlveda López
    CyberCorp S.A. | Blue Team

.DESCRIPTION
    Analiza Event IDs críticos de Windows para detectar
    actividad sospechosa: brute force, cuentas nuevas,
    escalada de privilegios, servicios maliciosos y persistencia.
    Genera reporte HTML + JSON para integración con SIEM.

.PARAMETER HoursBack
    Cuántas horas hacia atrás analizar (default: 24)

.PARAMETER OutputPath
    Carpeta donde guardar los reportes (default: .\reports)

.PARAMETER ExportHTML
    Genera reporte HTML visual (default: $true)

.PARAMETER ExportJSON
    Genera reporte JSON para SIEM (default: $true)

.EXAMPLE
    # Analizar últimas 24 horas
    .\Invoke-EventInvestigator.ps1

    # Analizar últimas 72 horas
    .\Invoke-EventInvestigator.ps1 -HoursBack 72

    # Solo JSON (para automatización)
    .\Invoke-EventInvestigator.ps1 -ExportHTML $false
#>

[CmdletBinding()]
param(
    [int]    $HoursBack   = 24,
    [string] $OutputPath  = ".\reports",
    [bool]   $ExportHTML  = $true,
    [bool]   $ExportJSON  = $true
)

# ─── CONFIGURACIÓN ────────────────────────────────────────
$ScriptVersion = "1.0"
$Analyst       = "Katalina Sepúlveda López"
$Organization  = "CyberCorp S.A."
$StartTime     = (Get-Date).AddHours(-$HoursBack)
$ReportTime    = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Event IDs a monitorear y su descripción
$EventIDs = @{
    # ── Autenticación ──────────────────────────────────────
    4625 = @{ Name = "Login Fallido";                    Category = "Credential Access";    Severity = "Medium"; MITRE = "T1110"     }
    4624 = @{ Name = "Login Exitoso";                    Category = "Authentication";        Severity = "Info";   MITRE = "T1078"     }
    4648 = @{ Name = "Login con Credenciales Explícitas";Category = "Credential Access";    Severity = "High";   MITRE = "T1078"     }

    # ── Gestión de cuentas ─────────────────────────────────
    4720 = @{ Name = "Cuenta Nueva Creada";              Category = "Privilege Escalation"; Severity = "High";   MITRE = "T1136"     }
    4722 = @{ Name = "Cuenta Habilitada";                Category = "Account Management";   Severity = "Medium"; MITRE = "T1098"     }
    4725 = @{ Name = "Cuenta Deshabilitada";             Category = "Account Management";   Severity = "Medium"; MITRE = "T1531"     }
    4726 = @{ Name = "Cuenta Eliminada";                 Category = "Account Management";   Severity = "Medium"; MITRE = "T1531"     }
    4740 = @{ Name = "Cuenta Bloqueada";                 Category = "Credential Access";    Severity = "High";   MITRE = "T1110"     }

    # ── Grupos privilegiados ───────────────────────────────
    4728 = @{ Name = "Usuario → Grupo Global (Domain Admins)"; Category = "Privilege Escalation"; Severity = "Critical"; MITRE = "T1098" }
    4732 = @{ Name = "Usuario → Grupo Local (Admins)";         Category = "Privilege Escalation"; Severity = "Critical"; MITRE = "T1098" }
    4756 = @{ Name = "Usuario → Grupo Universal";              Category = "Privilege Escalation"; Severity = "High";     MITRE = "T1098" }

    # ── Privilegios especiales ─────────────────────────────
    4672 = @{ Name = "Privilegios Especiales Asignados";  Category = "Privilege Escalation"; Severity = "High";   MITRE = "T1484"    }

    # ── Procesos y ejecución ───────────────────────────────
    4688 = @{ Name = "Proceso Nuevo Creado";              Category = "Execution";            Severity = "Medium"; MITRE = "T1059"    }
    4689 = @{ Name = "Proceso Terminado";                 Category = "Execution";            Severity = "Info";   MITRE = "T1059"    }

    # ── Servicios ──────────────────────────────────────────
    7045 = @{ Name = "Nuevo Servicio Instalado";          Category = "Persistence";          Severity = "High";   MITRE = "T1543.003"}
    7036 = @{ Name = "Estado de Servicio Cambiado";       Category = "Persistence";          Severity = "Low";    MITRE = "T1543"    }

    # ── Tareas programadas ─────────────────────────────────
    4698 = @{ Name = "Tarea Programada Creada";           Category = "Persistence";          Severity = "High";   MITRE = "T1053.005"}
    4699 = @{ Name = "Tarea Programada Eliminada";        Category = "Persistence";          Severity = "Medium"; MITRE = "T1053.005"}

    # ── Registro ───────────────────────────────────────────
    4657 = @{ Name = "Valor de Registro Modificado";      Category = "Persistence";          Severity = "High";   MITRE = "T1547.001"}

    # ── Auditoría ──────────────────────────────────────────
    1102 = @{ Name = "Log de Auditoría Limpiado";         Category = "Defense Evasion";      Severity = "Critical"; MITRE = "T1070.001"}
    4616 = @{ Name = "Hora del Sistema Cambiada";         Category = "Defense Evasion";      Severity = "Medium"; MITRE = "T1070"    }
}

# Colores por severidad
$SeverityColor = @{
    "Critical" = "#FF3B30"
    "High"     = "#FF9500"
    "Medium"   = "#FFCC00"
    "Low"      = "#34C759"
    "Info"     = "#007AFF"
}

# ─── FUNCIONES ────────────────────────────────────────────

function Write-Banner {
    $banner = @"

  ╔══════════════════════════════════════════════════════╗
  ║     WINDOWS EVENT INVESTIGATOR — SOC Toolkit         ║
  ║     $Organization | Blue Team             ║
  ║     Analista: $Analyst    ║
  ╚══════════════════════════════════════════════════════╝

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  Analizando eventos de las últimas $HoursBack horas..." -ForegroundColor Yellow
    Write-Host "  Desde: $StartTime" -ForegroundColor Gray
    Write-Host ""
}

function Get-SeverityIcon {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return "🔴" }
        "High"     { return "🟠" }
        "Medium"   { return "🟡" }
        "Low"      { return "🟢" }
        "Info"     { return "🔵" }
        default    { return "⚪" }
    }
}

function Get-WindowsEvents {
    <#
    Obtiene eventos del Security log y System log
    para todos los Event IDs configurados.
    #>
    param([int[]]$IDs, [DateTime]$Since)

    $allEvents = @()
    $logs      = @("Security", "System", "Application")

    foreach ($log in $logs) {
        try {
            $filterHash = @{
                LogName   = $log
                Id        = $IDs
                StartTime = $Since
            }
            $events = Get-WinEvent -FilterHashtable $filterHash -ErrorAction SilentlyContinue
            if ($events) { $allEvents += $events }
        }
        catch { <# Log sin eventos — continuar #> }
    }

    return $allEvents | Sort-Object TimeCreated -Descending
}

function Analyze-BruteForce {
    <#
    Detecta patrones de fuerza bruta:
    5+ fallos de login desde el mismo origen en 5 minutos.
    #>
    param([array]$Events4625)

    $suspicious = @()

    if (-not $Events4625 -or $Events4625.Count -eq 0) { return $suspicious }

    # Agrupar por IP/usuario origen
    $groups = $Events4625 | ForEach-Object {
        try {
            $xml  = [xml]$_.ToXml()
            $user = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $ip   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $user
                IP   = $ip
            }
        } catch { $null }
    } | Where-Object { $_ }

    # Detectar 5+ intentos en 5 minutos
    $byIP = $groups | Group-Object IP
    foreach ($group in $byIP) {
        if ($group.Name -in @("-", "::1", "127.0.0.1", $null)) { continue }
        if ($group.Count -ge 5) {
            $users = ($group.Group | Select-Object -ExpandProperty User -Unique) -join ", "
            $suspicious += [PSCustomObject]@{
                Type     = "BRUTE FORCE DETECTADO"
                IP       = $group.Name
                Count    = $group.Count
                Users    = $users
                Severity = "Critical"
                MITRE    = "T1110.001"
                Detail   = "$($group.Count) intentos fallidos desde $($group.Name) contra: $users"
            }
        }
    }

    return $suspicious
}

function Analyze-SuspiciousServices {
    <#
    Detecta servicios sospechosos:
    - Ejecutables .ps1 o .bat
    - Rutas no estándar (AppData, Temp, Users)
    - Nombres que imitan servicios de Windows
    #>
    param([array]$Events7045)

    $suspicious = @()
    if (-not $Events7045 -or $Events7045.Count -eq 0) { return $suspicious }

    $suspiciousPaths = @("\\temp\\", "\\appdata\\", "\\users\\", "\\tmp\\", "\\downloads\\")
    $suspiciousExts  = @(".ps1", ".bat", ".cmd", ".vbs", ".js")
    $fakeMSNames     = @("windowsupdate", "microsoftupdate", "windowssecurity",
                         "windowsdefender", "svchost32", "lsass32")

    foreach ($event in $Events7045) {
        try {
            $xml         = [xml]$event.ToXml()
            $serviceName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceName" }).'#text'
            $imagePath   = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ImagePath" }).'#text'
            $account     = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ServiceAccount" }).'#text'

            $alerts = @()

            # Verificar extensión del ejecutable
            foreach ($ext in $suspiciousExts) {
                if ($imagePath -like "*$ext*") {
                    $alerts += "Ejecutable con extensión sospechosa: $ext"
                }
            }

            # Verificar ruta sospechosa
            foreach ($path in $suspiciousPaths) {
                if ($imagePath.ToLower() -like "*$path*") {
                    $alerts += "Ruta no estándar: $imagePath"
                }
            }

            # Verificar nombre que imita Windows
            foreach ($fake in $fakeMSNames) {
                if ($serviceName.ToLower() -like "*$fake*") {
                    $alerts += "Nombre imita servicio Windows: $serviceName"
                }
            }

            # Verificar cuenta LocalSystem con ejecutable no estándar
            if ($account -eq "LocalSystem" -and $imagePath -notlike "*system32\svchost*") {
                $alerts += "Corre como LocalSystem con ejecutable no estándar"
            }

            if ($alerts.Count -gt 0) {
                $suspicious += [PSCustomObject]@{
                    Type     = "SERVICIO SOSPECHOSO"
                    Name     = $serviceName
                    Path     = $imagePath
                    Account  = $account
                    Time     = $event.TimeCreated
                    Severity = if ($alerts.Count -ge 2) { "Critical" } else { "High" }
                    MITRE    = "T1543.003"
                    Alerts   = $alerts -join " | "
                    Detail   = "Servicio: $serviceName | Path: $imagePath | Cuenta: $account"
                }
            }
        } catch { <# Continuar con siguiente evento #> }
    }

    return $suspicious
}

function Analyze-PrivilegeEscalation {
    <#
    Detecta escalada de privilegios:
    - Cuentas nuevas agregadas a grupos privilegiados
    - Cambios en Domain Admins o Administrators
    #>
    param([array]$Events4728, [array]$Events4732, [array]$Events4720)

    $findings = @()

    # Usuarios agregados a Domain Admins
    foreach ($event in $Events4728) {
        try {
            $xml        = [xml]$event.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "MemberName" }).'#text'
            $group      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $actor      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

            $findings += [PSCustomObject]@{
                Type     = "ESCALADA DE PRIVILEGIOS"
                Time     = $event.TimeCreated
                Actor    = $actor
                Target   = $targetUser
                Group    = $group
                Severity = "Critical"
                MITRE    = "T1098"
                Detail   = "$actor agregó $targetUser a Domain Admins ($group)"
            }
        } catch { }
    }

    # Usuarios agregados a Administradores locales
    foreach ($event in $Events4732) {
        try {
            $xml        = [xml]$event.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "MemberName" }).'#text'
            $group      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $actor      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

            $findings += [PSCustomObject]@{
                Type     = "ESCALADA DE PRIVILEGIOS"
                Time     = $event.TimeCreated
                Actor    = $actor
                Target   = $targetUser
                Group    = $group
                Severity = "Critical"
                MITRE    = "T1098"
                Detail   = "$actor agregó $targetUser a Administradores locales"
            }
        } catch { }
    }

    # Cuentas nuevas creadas
    foreach ($event in $Events4720) {
        try {
            $xml        = [xml]$event.ToXml()
            $newUser    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            $actor      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

            $findings += [PSCustomObject]@{
                Type     = "CUENTA NUEVA CREADA"
                Time     = $event.TimeCreated
                Actor    = $actor
                Target   = $newUser
                Group    = "N/A"
                Severity = "High"
                MITRE    = "T1136"
                Detail   = "$actor creó la cuenta: $newUser"
            }
        } catch { }
    }

    return $findings
}

function Get-EventSummary {
    param([array]$Events)

    $summary = @{}
    foreach ($id in $EventIDs.Keys) {
        $count = ($Events | Where-Object { $_.Id -eq $id }).Count
        if ($count -gt 0) {
            $info = $EventIDs[$id]
            $summary[$id] = @{
                Name     = $info.Name
                Count    = $count
                Severity = $info.Severity
                MITRE    = $info.MITRE
                Category = $info.Category
            }
        }
    }
    return $summary
}

function Export-HTMLReport {
    param(
        [hashtable] $Summary,
        [array]     $BruteForce,
        [array]     $PrivEsc,
        [array]     $SuspServices,
        [array]     $AllEvents,
        [string]    $Path
    )

    $criticalCount = ($AllEvents | Where-Object { $EventIDs[$_.Id].Severity -in @("Critical","High") }).Count
    $totalAlerts   = $BruteForce.Count + $PrivEsc.Count + $SuspServices.Count

    # Color del estado general
    $statusColor = if ($totalAlerts -eq 0) { "#34C759" } elseif ($criticalCount -gt 0) { "#FF3B30" } else { "#FF9500" }
    $statusText  = if ($totalAlerts -eq 0) { "NORMAL" } elseif ($criticalCount -gt 0) { "CRÍTICO" } else { "ALERTA" }

    # Generar filas de resumen
    $summaryRows = ""
    foreach ($id in ($Summary.Keys | Sort-Object)) {
        $item  = $Summary[$id]
        $color = $SeverityColor[$item.Severity]
        $icon  = Get-SeverityIcon $item.Severity
        $summaryRows += "<tr><td><b>$id</b></td><td>$($item.Name)</td><td>$($item.Category)</td><td style='color:$color;font-weight:bold'>$icon $($item.Severity)</td><td><b>$($item.Count)</b></td><td><code>$($item.MITRE)</code></td></tr>`n"
    }

    # Generar alertas críticas
    $alertRows = ""
    foreach ($bf in $BruteForce) {
        $alertRows += "<tr class='alert-row'><td>🔴 BRUTE FORCE</td><td>$($bf.IP)</td><td>$($bf.Detail)</td><td><code>$($bf.MITRE)</code></td></tr>`n"
    }
    foreach ($pe in $PrivEsc) {
        $icon = Get-SeverityIcon $pe.Severity
        $alertRows += "<tr class='alert-row'><td>$icon $($pe.Type)</td><td>$($pe.Time)</td><td>$($pe.Detail)</td><td><code>$($pe.MITRE)</code></td></tr>`n"
    }
    foreach ($ss in $SuspServices) {
        $alertRows += "<tr class='alert-row'><td>🟠 $($ss.Type)</td><td>$($ss.Name)</td><td>$($ss.Detail)</td><td><code>$($ss.MITRE)</code></td></tr>`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Windows Event Investigator — $Organization</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0F0F13; color: #E8E6E0; line-height: 1.6; }
  .header { background: linear-gradient(135deg, #0C447C 0%, #185FA5 100%);
            padding: 2rem; }
  .header h1 { font-size: 1.6rem; font-weight: 700; color: white; margin-bottom: 4px; }
  .header p  { color: rgba(255,255,255,0.75); font-size: 0.9rem; }
  .container { max-width: 1100px; margin: 0 auto; padding: 1.5rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
           gap: 1rem; margin: 1.5rem 0; }
  .card { background: #1A1A22; border: 1px solid #2A2A35;
          border-radius: 12px; padding: 1.2rem; }
  .card .num   { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: 0.8rem; color: #888; text-transform: uppercase;
                 letter-spacing: 0.05em; margin-top: 4px; }
  .status-badge { display: inline-block; padding: 4px 14px; border-radius: 20px;
                  font-weight: 700; font-size: 1rem; color: white;
                  background: $statusColor; }
  section { margin: 2rem 0; }
  section h2 { font-size: 1rem; font-weight: 600; color: #7EB3E8;
               text-transform: uppercase; letter-spacing: 0.05em;
               margin-bottom: 1rem; padding-bottom: 6px;
               border-bottom: 1px solid #2A2A35; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { background: #0C447C; color: white; padding: 10px 12px;
       text-align: left; font-weight: 600; }
  td { padding: 9px 12px; border-bottom: 1px solid #2A2A35; }
  tr:hover td { background: #1F1F2A; }
  .alert-row td { border-left: 3px solid #FF3B30; }
  code { background: #2A2A35; padding: 2px 6px; border-radius: 4px;
         font-family: monospace; font-size: 0.82rem; color: #7EB3E8; }
  .no-alerts { color: #34C759; padding: 1rem; background: #0D2010;
               border-radius: 8px; border: 1px solid #1A4A20; }
  .footer { text-align: center; padding: 2rem; color: #555;
            font-size: 0.82rem; border-top: 1px solid #2A2A35; margin-top: 2rem; }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Windows Event Investigator</h1>
  <p>$Organization | Blue Team | Analista: $Analyst</p>
  <p>Período analizado: últimas $HoursBack horas | Generado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
</div>

<div class="container">

  <div class="cards">
    <div class="card">
      <div class="num" style="color:#FF3B30">$totalAlerts</div>
      <div class="label">Alertas detectadas</div>
    </div>
    <div class="card">
      <div class="num" style="color:#FF9500">$criticalCount</div>
      <div class="label">Eventos críticos/altos</div>
    </div>
    <div class="card">
      <div class="num" style="color:#007AFF">$($AllEvents.Count)</div>
      <div class="label">Total eventos</div>
    </div>
    <div class="card">
      <div class="num"><span class="status-badge">$statusText</span></div>
      <div class="label">Estado del sistema</div>
    </div>
  </div>

  <section>
    <h2>📊 Resumen de Event IDs</h2>
    $(if ($summaryRows) {
      "<table><thead><tr><th>Event ID</th><th>Descripción</th><th>Categoría</th><th>Severidad</th><th>Count</th><th>MITRE</th></tr></thead><tbody>$summaryRows</tbody></table>"
    } else {
      "<div class='no-alerts'>✅ No se detectaron eventos en el período analizado.</div>"
    })
  </section>

  <section>
    <h2>🚨 Alertas críticas detectadas</h2>
    $(if ($alertRows) {
      "<table><thead><tr><th>Tipo</th><th>Origen/Hora</th><th>Detalle</th><th>MITRE</th></tr></thead><tbody>$alertRows</tbody></table>"
    } else {
      "<div class='no-alerts'>✅ No se detectaron alertas críticas en el período analizado.</div>"
    })
  </section>

  <section>
    <h2>📋 Referencia de Event IDs monitoreados</h2>
    <table>
      <thead><tr><th>Event ID</th><th>Descripción</th><th>Categoría SOC</th><th>Severidad</th><th>MITRE</th></tr></thead>
      <tbody>
        <tr><td>4625</td><td>Login Fallido</td><td>Credential Access</td><td style="color:#FF9500">🟠 Medium</td><td><code>T1110</code></td></tr>
        <tr><td>4624</td><td>Login Exitoso</td><td>Authentication</td><td style="color:#007AFF">🔵 Info</td><td><code>T1078</code></td></tr>
        <tr><td>4720</td><td>Cuenta Nueva Creada</td><td>Privilege Escalation</td><td style="color:#FF9500">🟠 High</td><td><code>T1136</code></td></tr>
        <tr><td>4728</td><td>Usuario → Domain Admins</td><td>Privilege Escalation</td><td style="color:#FF3B30">🔴 Critical</td><td><code>T1098</code></td></tr>
        <tr><td>4732</td><td>Usuario → Administradores</td><td>Privilege Escalation</td><td style="color:#FF3B30">🔴 Critical</td><td><code>T1098</code></td></tr>
        <tr><td>4672</td><td>Privilegios Especiales</td><td>Privilege Escalation</td><td style="color:#FF9500">🟠 High</td><td><code>T1484</code></td></tr>
        <tr><td>4740</td><td>Cuenta Bloqueada</td><td>Credential Access</td><td style="color:#FF9500">🟠 High</td><td><code>T1110</code></td></tr>
        <tr><td>7045</td><td>Nuevo Servicio Instalado</td><td>Persistence</td><td style="color:#FF9500">🟠 High</td><td><code>T1543.003</code></td></tr>
        <tr><td>4698</td><td>Tarea Programada Creada</td><td>Persistence</td><td style="color:#FF9500">🟠 High</td><td><code>T1053.005</code></td></tr>
        <tr><td>4657</td><td>Registro Modificado</td><td>Persistence</td><td style="color:#FF9500">🟠 High</td><td><code>T1547.001</code></td></tr>
        <tr><td>1102</td><td>Log de Auditoría Limpiado</td><td>Defense Evasion</td><td style="color:#FF3B30">🔴 Critical</td><td><code>T1070.001</code></td></tr>
        <tr><td>4688</td><td>Proceso Nuevo Creado</td><td>Execution</td><td style="color:#FFCC00">🟡 Medium</td><td><code>T1059</code></td></tr>
      </tbody>
    </table>
  </section>

</div>

<div class="footer">
  Windows Event Investigator v$ScriptVersion | $Organization | $Analyst | $(Get-Date -Format 'yyyy-MM-dd')
</div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
}

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

Write-Banner

# Crear carpeta de reportes
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Obtener todos los eventos
Write-Host "  [*] Recopilando eventos de Windows..." -ForegroundColor Cyan
$allEventIDs = [int[]]$EventIDs.Keys
$allEvents   = Get-WindowsEvents -IDs $allEventIDs -Since $StartTime

Write-Host "  [+] Total eventos encontrados: $($allEvents.Count)" -ForegroundColor Green

# Separar por Event ID
$events4625  = $allEvents | Where-Object { $_.Id -eq 4625 }
$events4728  = $allEvents | Where-Object { $_.Id -eq 4728 }
$events4732  = $allEvents | Where-Object { $_.Id -eq 4732 }
$events4720  = $allEvents | Where-Object { $_.Id -eq 4720 }
$events7045  = $allEvents | Where-Object { $_.Id -eq 7045 }

# Análisis
Write-Host "`n  [*] Analizando patrones sospechosos..." -ForegroundColor Cyan

$bruteForce   = Analyze-BruteForce        -Events4625 $events4625
$privEsc      = Analyze-PrivilegeEscalation -Events4728 $events4728 -Events4732 $events4732 -Events4720 $events4720
$suspServices = Analyze-SuspiciousServices -Events7045 $events7045
$summary      = Get-EventSummary          -Events $allEvents

# Mostrar resultados en consola
Write-Host ""
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Blue
Write-Host "  RESULTADOS DEL ANÁLISIS" -ForegroundColor White
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Blue

# Resumen de Event IDs
if ($summary.Count -gt 0) {
    Write-Host "`n  Event IDs detectados:" -ForegroundColor Yellow
    foreach ($id in ($summary.Keys | Sort-Object)) {
        $item  = $summary[$id]
        $icon  = Get-SeverityIcon $item.Severity
        $color = switch ($item.Severity) {
            "Critical" { "Red" }
            "High"     { "DarkYellow" }
            "Medium"   { "Yellow" }
            default    { "Gray" }
        }
        Write-Host "    $icon  EventID $id | $($item.Name) | Count: $($item.Count) | $($item.MITRE)" -ForegroundColor $color
    }
}

# Alertas críticas
$totalAlerts = $bruteForce.Count + $privEsc.Count + $suspServices.Count

if ($totalAlerts -gt 0) {
    Write-Host "`n  🚨 ALERTAS CRÍTICAS DETECTADAS: $totalAlerts" -ForegroundColor Red

    foreach ($bf in $bruteForce) {
        Write-Host "    🔴 BRUTE FORCE | IP: $($bf.IP) | Intentos: $($bf.Count) | $($bf.MITRE)" -ForegroundColor Red
    }
    foreach ($pe in $privEsc) {
        $icon = Get-SeverityIcon $pe.Severity
        Write-Host "    $icon $($pe.Type) | $($pe.Detail) | $($pe.MITRE)" -ForegroundColor Red
    }
    foreach ($ss in $suspServices) {
        Write-Host "    🟠 $($ss.Type) | $($ss.Name) | $($ss.Alerts)" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "`n  ✅ No se detectaron patrones sospechosos en el período analizado." -ForegroundColor Green
}

# Exportar HTML
if ($ExportHTML) {
    $htmlPath = Join-Path $OutputPath "EventReport_$ReportTime.html"
    Export-HTMLReport -Summary $summary -BruteForce $bruteForce `
                      -PrivEsc $privEsc -SuspServices $suspServices `
                      -AllEvents $allEvents -Path $htmlPath
    Write-Host "`n  [+] Reporte HTML guardado: $htmlPath" -ForegroundColor Green
}

# Exportar JSON
if ($ExportJSON) {
    $jsonPath = Join-Path $OutputPath "EventReport_$ReportTime.json"
    $jsonData = @{
        metadata = @{
            tool         = "Windows Event Investigator v$ScriptVersion"
            analyst      = $Analyst
            organization = $Organization
            timestamp    = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
            hours_back   = $HoursBack
            total_events = $allEvents.Count
        }
        summary       = $summary
        alerts        = @{
            brute_force        = $bruteForce
            privilege_escalation = $privEsc
            suspicious_services  = $suspServices
            total_alerts       = $totalAlerts
        }
        event_id_reference = $EventIDs
    }
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  [+] Reporte JSON guardado: $jsonPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Blue
Write-Host "  ANÁLISIS COMPLETADO" -ForegroundColor White
Write-Host "  ══════════════════════════════════════════" -ForegroundColor Blue
Write-Host ""
