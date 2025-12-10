# DScan: Herramienta de Triage Rápido para Pentesting

Dcan es una herramienta Python para automatizar el reconocimiento de puertos y generar reportes de vectores de ataque, optimizado para entornos de CTF y HTB.

## 🌟 Valor Añadido
* **Velocidad Extrema:** Utiliza flags agresivos de Nmap (`-T5`, `--min-rate 5000`) para minimizar el tiempo de escaneo.
* **Guía Operativa:** Genera automáticamente un análisis de priorización (Triage) por puerto, sugiriendo la herramienta y acción más probable (Ej: HTTP -> Gobuster).
* **Documentación Instantánea:** Exporta el reporte técnico de la enumeración a formato Markdown (`-o md`), reduciendo el tiempo de documentación en más del 80%.

## 🛠️ Instalación
1. Clona el repositorio: `git clone https://github.com/danielbarbeytotorres/DScan-Triage`
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

  ## 🚀 Uso
  Ejemplo 1 - Escaneo básico y reporte en terminal: `dscan 10.10.10.123`
  Ejemplo 2 - Generar reporte Markdown para el write-up: `dscan 10.10.10.123 -o md`
