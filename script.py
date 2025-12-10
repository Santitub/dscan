import nmap
import argparse
import json
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

CHEAT_SHEET = {
    'ftp': {
        'tool': 'ftp <IP>',
        'action': 'Verificar acceso Anonymous. Descargar archivos si es posible.',
        'path': 'wget -r ftp://anonymous:anonymous@<IP>/'
    },
    'ssh': {
        'tool': 'ssh user@<IP>',
        'action': 'Revisar versión para CVEs. Rara vez brute-force salvo usuario conocido.',
        'path': 'searchsploit OpenSSH <version>'
    },
    'http': {
        'tool': 'Gobuster / Wappalyzer',
        'action': 'Fuzzing de directorios y subdominios. Revisar robots.txt y código fuente.',
        'path': 'gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt'
    },
    'https': {
        'tool': 'Gobuster / SSLScan',
        'action': 'Igual que HTTP. Verificar certificados y Heartbleed si es antiguo.',
        'path': 'gobuster dir -u https://<IP> -k -w ...'
    },
    'smb': {
        'tool': 'smbclient / crackmapexec',
        'action': 'Listar shares. Verificar Null Session. Buscar vulnerabilidades críticas (EternalBlue).',
        'path': 'smbmap -H <IP> -u "null"'
    },
    'mysql': {
        'tool': 'mysql',
        'action': 'Intentar acceso root sin pass o credenciales por defecto.',
        'path': 'mysql -h <IP> -u root'
    },
    'rdp': {
        'tool': 'xfreerdp',
        'action': 'Intentar acceso con credenciales (si se tienen). BlueKeep en versiones viejas.',
        'path': 'xfreerdp /v:<IP> /u:user /p:pass'
    },
}

def obtener_argumentos():
    """Parsea los argumentos. La IP es posicional (sin -t)."""
    parser = argparse.ArgumentParser(description='[Network Triager] Escáner de Puertos Automatizado para HTB/OSCP.')
    parser.add_argument('target', help='IP del objetivo (Ej: 10.10.10.10)')
    parser.add_argument('-o', '--output', choices=['screen', 'md', 'json'], default='screen', help='Formato de salida (screen, md, json)')
    return parser.parse_args()

def escanear_objetivo(target):
    """Ejecuta Nmap con perfil agresivo y scripts por defecto (-sC)."""
    nm = nmap.PortScanner()
    
    print(f"{Fore.CYAN}[*] Iniciando análisis sobre: {Fore.WHITE}{target}")
    print(f"{Fore.YELLOW}[!] Perfil: {Fore.WHITE}Agresivo (-T5, min-rate 5000) + Scripts Default (-sC)")
    
    try:
        nm.scan(target, arguments='-sS -sV -sC -n -Pn -T5 --min-rate 5000 --open')
    except Exception as e:
        print(f"{Fore.RED}[X] Error crítico en Nmap: {e}")
        sys.exit(1)
        
    return nm

def procesar_datos(nm):
    """Estructura la información cruda de Nmap."""
    datos_estructurados = []
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                service = nm[host][proto][port]
                nombre_servicio = service['name']
                producto = service['product']
                version = service['version']
                banner = f"{producto} {version}".strip()
                script_output = service.get('script', {}) 
                
                recomendacion = CHEAT_SHEET.get(nombre_servicio, {
                    'tool': 'Google / Searchsploit',
                    'action': 'Servicio no común. Investigar manualmente versión y puerto.',
                    'path': f'searchsploit {producto} {version}'
                })
                
                datos_estructurados.append({
                    "puerto": port,
                    "protocolo": proto,
                    "servicio": nombre_servicio,
                    "banner": banner,
                    "scripts": script_output,
                    "guia": recomendacion,
                })
    return datos_estructurados

def reporte_pantalla(target, datos):
    """Muestra resultados en terminal (Formal)."""
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}[+] REPORTE DE ESCANEO: {Style.BRIGHT}{target}")
    print(f"{Fore.GREEN}{'='*60}")
    
    if not datos:
        print(f"{Fore.RED}[!] No se detectaron puertos abiertos.")
        return

    for item in datos:
        print(f"\n{Fore.MAGENTA}➤ PUERTO {item['puerto']}/{item['protocolo'].upper()} : {Fore.WHITE}{item['servicio']} {Fore.LIGHTBLACK_EX}({item['banner']})")
        
        if item['scripts']:
            print(f"{Fore.LIGHTBLACK_EX}   └── [NSE Info]:")
            for k, v in item['scripts'].items():
                v_clean = v.strip().replace('\n', ' | ') 
                print(f"{Fore.LIGHTBLACK_EX}       * {k}: {v_clean}")

        print(f"{Fore.YELLOW}   [Guía Operativa]:")
        print(f"{Fore.CYAN}    🛠  Herramienta: {Fore.WHITE}{item['guia']['tool']}")
        print(f"{Fore.CYAN}    ⚡  Acción:      {Fore.WHITE}{item['guia']['action']}")
        print(f"{Fore.CYAN}    💻  Comando:     {Fore.WHITE}{item['guia']['path']}")

def reporte_markdown(target, datos):
    """Genera archivo Markdown para documentación."""
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    filename = f"Scan_{target}_{datetime.now().strftime('%H%M%S')}.md"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"# Reporte Técnico de Objetivo: {target}\n\n")
        f.write(f"**Fecha:** {fecha}\n")
        f.write(f"**Estrategia:** Escaneo Rápido TCP + Scripts Default\n\n")
        f.write("## 1. Resumen de Servicios\n\n")
        
        if not datos:
            f.write("> No se encontraron puertos abiertos.\n")
        else:
            f.write("| Puerto | Servicio | Versión | Notas |\n")
            f.write("|---|---|---|---|\n")
            for item in datos:
                f.write(f"| {item['puerto']} | {item['servicio']} | {item['banner']} | - |\n")
        
        f.write("\n## 2. Análisis Detallado y Vectores de Ataque\n\n")
        
        for item in datos:
            f.write(f"### 🛡️ Puerto {item['puerto']} - {item['servicio']}\n")
            f.write(f"- **Banner Completo:** `{item['banner']}`\n")
            
            if item['scripts']:
                f.write("- **Hallazgos Automatizados (NSE):**\n")
                f.write("```bash\n")
                for k, v in item['scripts'].items():
                    f.write(f"{k}:\n{v}\n")
                f.write("```\n")

            f.write(f"#### 📋 Procedimiento Recomendado\n")
            f.write(f"* **Acción:** {item['guia']['action']}\n")
            f.write(f"* **Herramienta:** `{item['guia']['tool']}`\n")
            f.write(f"* **Comando Sugerido:** `{item['guia']['path']}`\n\n")
            f.write("---\n")

    print(f"\n{Fore.GREEN}[+] Archivo generado con éxito: {Style.BRIGHT}{filename}")
    
    
def reporte_json(target, datos):
    """Genera archivo JSON para procesamiento."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename_json = f"scan_{target}_{timestamp}.json"
    
    reporte_final = {
        "target": target,
        "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "ports": datos
    }

    with open(filename_json, "w", encoding='utf-8') as jf:
        json.dump(reporte_final, jf, indent=4, ensure_ascii=False) 
        
    print(f"\n{Fore.GREEN}[+] Reporte JSON guardado en: {filename_json}")


if __name__ == "__main__":
    args = obtener_argumentos()
    nm_scan = escanear_objetivo(args.target)
    
    if nm_scan:
        datos = procesar_datos(nm_scan)
        
        if args.output == 'screen':
            reporte_pantalla(args.target, datos)
        elif args.output == 'md':
            reporte_markdown(args.target, datos)
        elif args.output == 'json':
            reporte_json(args.target, datos)
