#!/usr/bin/env python3
"""
DScan: Herramienta de Triage Rápido para Pentesting
Script principal con validaciones, logging y robustez mejorada.
"""

import nmap
import argparse
import json
import sys
import re
import os
import ipaddress
import logging
from typing import List, Dict, Any, Optional
from fnmatch import fnmatch
from datetime import datetime
from colorama import Fore, Style, init

# Inicializar colorama y logging
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dscan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Constantes de tiempo
TIMESTAMP: str = datetime.now().strftime('%Y%m%d_%H%M%S')
DATE_FORMAT: str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Cheatsheet con patrones flexibles
CHEAT_SHEET: Dict[str, Dict[str, str]] = {
    'ftp': {
        'tool': 'ftp <IP>',
        'action': 'Verificar acceso Anonymous. Descargar archivos si es posible.',
        'path': 'wget -r ftp://anonymous:anonymous@<IP>/'
    },
    'ssh*': {
        'tool': 'ssh user@<IP>',
        'action': 'Revisar versión para CVEs. Rara vez brute-force salvo usuario conocido.',
        'path': 'searchsploit OpenSSH <version>'
    },
    'http*': {
        'tool': 'Gobuster / Wappalyzer',
        'action': 'Fuzzing de directorios y subdominios. Revisar robots.txt y código fuente.',
        'path': 'gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt'
    },
    'https*': {
        'tool': 'Gobuster / SSLScan',
        'action': 'Igual que HTTP. Verificar certificados y Heartbleed si es antiguo.',
        'path': 'gobuster dir -u https://<IP> -k -w ...'
    },
    'smb*': {
        'tool': 'smbclient / crackmapexec',
        'action': 'Listar shares. Verificar Null Session. Buscar vulnerabilidades críticas (EternalBlue).',
        'path': 'smbmap -H <IP> -u "null"'
    },
    'mysql*': {
        'tool': 'mysql',
        'action': 'Intentar acceso root sin pass o credenciales por defecto.',
        'path': 'mysql -h <IP> -u root'
    },
    'rdp*': {
        'tool': 'xfreerdp',
        'action': 'Intentar acceso con credenciales (si se tienen). BlueKeep en versiones viejas.',
        'path': 'xfreerdp /v:<IP> /u:user /p:pass'
    },
    '*sql*': {  # Captura MySQL, PostgreSQL, MSSQL, etc.
        'tool': 'Cliente SQL específico',
        'action': 'Verificar credenciales por defecto y enumerar bases de datos.',
        'path': 'mysql -h <IP> -u root -p  # o psql, sqlcmd, etc.'
    }
}

def validar_ip(target: str) -> str:
    """
    Valida que el target sea una IP válida.
    
    Args:
        target: String con la IP objetivo
        
    Returns:
        IP validada y sanitizada
        
    Raises:
        SystemExit: Si la IP es inválida
    """
    try:
        # Eliminar espacios y caracteres no válidos
        target_limpio = re.sub(r'[^\d.]', '', target.strip())
        ip_obj = ipaddress.ip_address(target_limpio)
        return str(ip_obj)
    except ValueError:
        logging.error(f"IP inválida: {target}")
        sys.exit(1)

def verificar_nmap() -> None:
    """
    Verifica que nmap esté instalado en el sistema.
    
    Raises:
        SystemExit: Si nmap no está disponible
    """
    try:
        nm = nmap.PortScanner()
        nm.scan('127.0.0.1', arguments='-p 80', timeout=10)
    except nmap.PortScannerError:
        logging.error("Nmap no está instalado o no es accesible. Instala con: apt install nmap")
        sys.exit(1)
    except Exception:
        # Nmap está instalado pero localhost:80 está cerrado (esperado)
        pass

def obtener_argumentos() -> argparse.Namespace:
    """
    Parsea los argumentos de línea de comandos con validación mejorada.
    
    Returns:
        Namespace con los argumentos parseados
    """
    parser = argparse.ArgumentParser(
        description='[Network Triager] Escáner de Puertos Automatizado para HTB/OSCP.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s 10.10.10.10
  %(prog)s 10.10.10.10 -o md --timeout 600
  %(prog)s 192.168.1.1 -o json -p 1-1000
        """
    )
    parser.add_argument(
        'target', 
        help='IP del objetivo (Ej: 10.10.10.10)'
    )
    parser.add_argument(
        '-o', '--output', 
        choices=['screen', 'md', 'json'], 
        default='screen', 
        help='Formato de salida (default: screen)'
    )
    parser.add_argument(
        '--timeout', 
        type=int, 
        default=300,
        help='Timeout del escaneo en segundos (default: 300)'
    )
    parser.add_argument(
        '-p', '--ports',
        help='Rango de puertos (Ej: 1-1024, 80,443). Por defecto: todos los puertos comunes'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose para depuración'
    )
    return parser.parse_args()

def escanear_objetivo(target: str, timeout: int, ports: Optional[str] = None) -> nmap.PortScanner:
    """
    Ejecuta Nmap con perfil agresivo y scripts por defecto (-sC).
    
    Args:
        target: IP válida del objetivo
        timeout: Timeout en segundos
        ports: Rango de puertos opcional
        
    Returns:
        Objeto PortScanner con resultados
        
    Raises:
        SystemExit: Si el escaneo falla críticamente
    """
    nm = nmap.PortScanner()
    
    # Construir argumentos de Nmap
    arguments = '-sS -sV -sC -n -Pn -T5 --min-rate 5000 --open'
    if ports:
        arguments += f' -p {ports}'
    
    logging.info(f"Iniciando análisis sobre: {target}")
    logging.info(f"Perfil: Agresivo (-T5, min-rate 5000) + Scripts Default (-sC)")
    
    try:
        nm.scan(target, arguments=arguments, timeout=timeout)
    except nmap.PortScannerError as e:
        logging.error(f"Error de Nmap: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error crítico inesperado: {e}")
        sys.exit(1)
        
    return nm

def procesar_datos(nm: nmap.PortScanner) -> List[Dict[str, Any]]:
    """
    Estructura la información cruda de Nmap.
    
    Args:
        nm: Objeto PortScanner con resultados
        
    Returns:
        Lista de diccionarios con datos procesados
    """
    datos_estructurados = []
    
    if not nm.all_hosts():
        logging.warning("No se detectaron hosts alcanzables")
        return datos_estructurados
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                # Validar rango de puerto
                if not (1 <= port <= 65535):
                    logging.warning(f"Puerto inválido detectado: {port}, ignorando")
                    continue
                
                service = nm[host][proto][port]
                nombre_servicio = service.get('name', 'unknown')
                producto = service.get('product', '')
                version = service.get('version', '')
                banner = f"{producto} {version}".strip()
                script_output = service.get('script', {}) 
                
                # Buscar recomendación usando fnmatch para patrones
                recomendacion = None
                for pattern, data in CHEAT_SHEET.items():
                    if fnmatch(nombre_servicio, pattern):
                        recomendacion = data.copy()  # Copiar para no modificar original
                        break
                
                if not recomendacion:
                    recomendacion = {
                        'tool': 'Google / Searchsploit',
                        'action': 'Servicio no común. Investigar manualmente versión y puerto.',
                        'path': f'searchsploit {producto} {version}'
                    }
                
                datos_estructurados.append({
                    "puerto": port,
                    "protocolo": proto,
                    "servicio": nombre_servicio,
                    "banner": banner,
                    "scripts": script_output,
                    "guia": recomendacion,
                })
    return datos_estructurados

def sanitizar_texto(texto: Any, para_markdown: bool = True) -> str:
    """
    Sanitiza texto para evitar caracteres problemáticos.
    
    Args:
        texto: Texto a sanitizar
        para_markdown: Si es para Markdown (más restrictivo)
        
    Returns:
        Texto sanitizado
    """
    texto_str = str(texto)
    # Eliminar caracteres de control
    texto_limpio = re.sub(r'[\x00-\x1F\x7F]', '', texto_str)
    
    if para_markdown:
        # Para Markdown, eliminar caracteres que rompan tablas
        return re.sub(r'[|`]', '', texto_limpio)
    
    return texto_limpio

def generar_nombre_archivo(target: str, extension: str) -> str:
    """
    Genera nombre de archivo seguro sanitizando el target.
    
    Args:
        target: IP del objetivo
        extension: Extensión del archivo
        
    Returns:
        Nombre de archivo seguro
    """
    target_seguro = target.replace('.', '_').replace('/', '_')
    return f"Scan_{target_seguro}_{TIMESTAMP}.{extension}"

def reporte_pantalla(target: str, datos: List[Dict[str, Any]]) -> None:
    """
    Muestra resultados en terminal con formato.
    
    Args:
        target: IP objetivo
        datos: Lista de puertos detectados
    """
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}[+] REPORTE DE ESCANEO: {Style.BRIGHT}{target}")
    print(f"{Fore.GREEN}{'='*60}")
    
    if not datos:
        print(f"{Fore.RED}[!] No se detectaron puertos abiertos.")
        return

    for item in datos:
        banner_limpio = sanitizar_texto(item['banner'], para_markdown=False)
        print(f"\n{Fore.MAGENTA}➤ PUERTO {item['puerto']}/{item['protocolo'].upper()} : {Fore.WHITE}{item['servicio']} {Fore.LIGHTBLACK_EX}({banner_limpio})")
        
        if item['scripts']:
            print(f"{Fore.LIGHTBLACK_EX}   └── [NSE Info]:")
            for k, v in item['scripts'].items():
                v_clean = sanitizar_texto(v, para_markdown=False)
                print(f"{Fore.LIGHTBLACK_EX}       * {k}: {v_clean}")

        print(f"{Fore.YELLOW}   [Guía Operativa]:")
        print(f"{Fore.CYAN}    🛠  Herramienta: {Fore.WHITE}{item['guia']['tool']}")
        print(f"{Fore.CYAN}    ⚡  Acción:      {Fore.WHITE}{item['guia']['action']}")
        print(f"{Fore.CYAN}    💻  Comando:     {Fore.WHITE}{item['guia']['path']}")

def reporte_markdown(target: str, datos: List[Dict[str, Any]]) -> None:
    """
    Genera archivo Markdown para documentación.
    
    Args:
        target: IP objetivo
        datos: Lista de puertos detectados
    """
    filename = generar_nombre_archivo(target, 'md')
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# Reporte Técnico de Objetivo: {target}\n\n")
            f.write(f"**Fecha:** {DATE_FORMAT}\n")
            f.write(f"**Estrategia:** Escaneo Rápido TCP + Scripts Default\n\n")
            f.write("## 1. Resumen de Servicios\n\n")
            
            if not datos:
                f.write("> No se encontraron puertos abiertos.\n")
            else:
                f.write("| Puerto | Servicio | Versión | Notas |\n")
                f.write("|---|---|---|---|\n")
                for item in datos:
                    servicio = sanitizar_texto(item['servicio'])
                    banner = sanitizar_texto(item['banner'])
                    f.write(f"| {item['puerto']} | {servicio} | {banner} | - |\n")
            
            f.write("\n## 2. Análisis Detallado y Vectores de Ataque\n\n")
            
            for item in datos:
                servicio = sanitizar_texto(item['servicio'])
                banner = sanitizar_texto(item['banner'])
                f.write(f"### 🛡️ Puerto {item['puerto']} - {servicio}\n")
                f.write(f"- **Banner Completo:** `{banner}`\n")
                
                if item['scripts']:
                    f.write("- **Hallazgos Automatizados (NSE):**\n")
                    f.write("```bash\n")
                    for k, v in item['scripts'].items():
                        script_safe = sanitizar_texto(v)
                        f.write(f"{k}:\n{script_safe}\n")
                    f.write("```\n")

                f.write(f"#### 📋 Procedimiento Recomendado\n")
                f.write(f"* **Acción:** {sanitizar_texto(item['guia']['action'])}\n")
                f.write(f"* **Herramienta:** `{sanitizar_texto(item['guia']['tool'])}`\n")
                f.write(f"* **Comando Sugerido:** `{sanitizar_texto(item['guia']['path'])}`\n\n")
                f.write("---\n")
        
        logging.info(f"Archivo Markdown generado: {filename}")
        print(f"\n{Fore.GREEN}[+] Archivo generado con éxito: {Style.BRIGHT}{filename}")
    
    except IOError as e:
        logging.error(f"No se pudo escribir archivo {filename}: {e}")
        sys.exit(1)

def reporte_json(target: str, datos: List[Dict[str, Any]]) -> None:
    """
    Genera archivo JSON para procesamiento (datos CRUDOS, sin sanitizar).
    
    Args:
        target: IP objetivo
        datos: Lista de puertos detectados
    """
    filename = generar_nombre_archivo(target, 'json')
    
    reporte_final = {
        "target": target,
        "date": DATE_FORMAT,
        "timestamp": TIMESTAMP,
        "ports": datos  # Datos sin sanitizar para procesamiento automatizado
    }

    try:
        with open(filename, "w", encoding='utf-8') as jf:
            json.dump(reporte_final, jf, indent=4, ensure_ascii=False) 
        
        logging.info(f"Archivo JSON generado: {filename}")
        print(f"\n{Fore.GREEN}[+] Reporte JSON guardado en: {filename}")
    
    except IOError as e:
        logging.error(f"No se pudo escribir archivo {filename}: {e}")
        sys.exit(1)

def main() -> None:
    """Función principal con manejo de errores global."""
    try:
        args = obtener_argumentos()
        
        # Configurar verbose si se solicitó
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Verificar dependencias
        verificar_nmap()
        
        # Validar IP
        target_validado = validar_ip(args.target)
        
        # Verificar si se ejecuta con sudo (recomendado)
        if os.geteuid() != 0:
            logging.warning("No se está ejecutando como root. El escaneo SYN puede fallar.")
            print(f"{Fore.YELLOW}[!] Advertencia: No se está ejecutando como root. El escaneo SYN puede fallar.{Fore.RESET}")
        
        # Ejecutar escaneo
        nm_scan = escanear_objetivo(target_validado, args.timeout, args.ports)
        
        # Procesar y generar reporte
        if nm_scan:
            datos = procesar_datos(nm_scan)
            
            if args.output == 'screen':
                reporte_pantalla(target_validado, datos)
            elif args.output == 'md':
                reporte_markdown(target_validado, datos)
            elif args.output == 'json':
                reporte_json(target_validado, datos)
        
        logging.info("Escaneo completado exitosamente")
        
    except KeyboardInterrupt:
        logging.warning("Escaneo cancelado por el usuario (Ctrl+C)")
        print(f"\n{Fore.YELLOW}[!] Escaneo cancelado por el usuario.{Fore.RESET}")
        sys.exit(130)
    except Exception as e:
        logging.error(f"Error inesperado: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()