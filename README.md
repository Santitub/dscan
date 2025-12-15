# DScan: Herramienta de Triage Rápido para Pentesting

Dcan es una herramienta Python para automatizar el reconocimiento de puertos y generar reportes de vectores de ataque, optimizado para entornos de CTF y HTB.

## 🌟 Valor Añadido
* **Velocidad Extrema:** Utiliza flags agresivos de Nmap (`-T5`, `--min-rate 5000`) para minimizar el tiempo de escaneo.
* **Guía Operativa:** Genera automáticamente un análisis de priorización (Triage) por puerto, sugiriendo la herramienta y acción más probable (Ej: HTTP -> Gobuster).
* **Documentación Instantánea:** Exporta el reporte técnico de la enumeración a formato Markdown (`-o md`), reduciendo el tiempo de documentación en más del 80%.
* **Verificaciones Inteligentes:** Valida automáticamente el entorno, dependencias y herramientas del sistema antes de ejecutar.

## 🛠️ Instalación
1. Clona el repositorio: `git clone https://github.com/danielbarbeytotorres/dscan`
2. Configura el entorno virtual (necesario por `sudo` y `pip`):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. (Opcional) Crea un enlace simbólico para acceso global:
   ```bash
   chmod +x dscan
   sudo ln -s $(pwd)/dscan /usr/local/bin/dscan
   ```

## 🔍 Verificación de Dependencias
Antes de ejecutar el escáner, puedes verificar que todo está configurado correctamente:

```bash
dscan --check-dependencies
```

Esto validará:
- ✅ Existencia del entorno virtual `./venv/`
- ✅ Instalación correcta de las dependencias de Python (`python-nmap`, `colorama`)
- ✅ Disponibilidad de Nmap en el sistema

Si falta algo, el script mostrará instrucciones específicas para solucionarlo.

## 🚀 Uso

### Ejemplos básicos:
```bash
# Escaneo básico y reporte en terminal
dscan 10.10.10.123

# Generar reporte Markdown para el write-up
dscan 10.10.10.123 -o md

# Exportar datos en formato JSON
dscan 10.10.10.123 -o json
```

### Verificación previa:
```bash
# Verificar entorno antes de escanear
dscan --check-dependencies

# Si todo está correcto, verás "[+] Entorno virtual encontrado ✓" y "[+] Nmap está instalado ✓"
```

El escáner realiza verificaciones automáticas antes de cada ejecución. Si detecta problemas, te mostrará exactamente qué falta y cómo solucionarlo.

## Resultado
![.](out.png)

Espero que a alguien le sea de utilidad esta herramienta!