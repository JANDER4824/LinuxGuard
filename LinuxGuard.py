#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Firewall Manager - Script de gestión de firewall para Linux basado en iptables
Autor: JANDER
Fecha: 03/05/2025
Descripción: Script interactivo para gestionar reglas de firewall en sistemas Linux
             usando IPtables. Requiere privilegios de root para ejecutarse.
"""

import os
import re
import sys
import time
import signal
import subprocess
import shutil
import shlex
from datetime import datetime

# Configuración global
LOG_FILE = "firewall_log.txt"
RESTORE_FILE = "restore_rules.sh"

# Colores para la terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Funciones de utilidad
def log_action(action):
    """Registra acciones en el archivo de log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {action}\n")

def check_root():
    """Verifica si el script se está ejecutando con privilegios root"""
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}Error: Este script requiere privilegios de root.{Colors.ENDC}")
        print(f"Por favor, ejecute: {Colors.BOLD}sudo python3 {sys.argv[0]}{Colors.ENDC}")
        sys.exit(1)

def check_dependencies():
    """Verifica que las dependencias necesarias estén instaladas"""
    if shutil.which("iptables") is None:
        print(f"{Colors.FAIL}Error: iptables no está instalado o no se encuentra en la ruta.{Colors.ENDC}")
        log_action("ERROR: iptables no disponible")
        sys.exit(1)

def execute_command(command):
    """Ejecuta un comando del sistema y devuelve su salida"""
    try:
        result = subprocess.run(
            shlex.split(command),
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"{Colors.FAIL}Error al ejecutar el comando: {e}{Colors.ENDC}")
        if isinstance(e, subprocess.CalledProcessError):
            print(f"Detalles: {e.stderr}")
            log_action(f"ERROR: {command} - {e.stderr}")
        else:
            log_action(f"ERROR: comando no encontrado - {command}")
        return None

def validate_ip(ip):
    """Valida que una dirección IP tenga el formato correcto"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if not re.match(pattern, ip):
        return False
    
    # Verificar cada octeto si no es una notación CIDR
    if '/' not in ip:
        octets = ip.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
    else:
        # Si tiene notación CIDR, validar IP y máscara
        address, mask = ip.split('/')
        octets = address.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False
        if not 0 <= int(mask) <= 32:
            return False
    
    return True

def validate_port(port):
    """Valida que un puerto sea un número entero entre 1 y 65535"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except ValueError:
        return False

def get_input(prompt, validator=None, error_message=None):
    """Obtiene y valida la entrada del usuario"""
    while True:
        value = input(prompt)
        if not validator or validator(value):
            return value
        print(f"{Colors.FAIL}{error_message}{Colors.ENDC}")

def clear_screen():
    """Limpia la pantalla de la terminal"""
    os.system('clear' if os.name == 'posix' else 'cls')

def show_banner():
    """Muestra el banner del programa"""
    clear_screen()
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("╔════════════════════════════════════════════╗")
    print("║         FIREWALL MANAGER v1.0              ║")
    print("║      Gestor de Firewall Linux con          ║")
    print("║           interfaz interactiva             ║")
    print("╚════════════════════════════════════════════╝")
    print(f"{Colors.ENDC}")

# Funciones del firewall
def show_rules():
    """Muestra las reglas actuales de iptables"""
    print(f"\n{Colors.BLUE}=== Reglas actuales de iptables ==={Colors.ENDC}")
    output = execute_command("iptables -L -v -n")
    if output:
        print(output)
    else:
        print(f"{Colors.WARNING}No se pudieron obtener las reglas actuales.{Colors.ENDC}")
    
    log_action("Visualización de reglas actuales")
    input("\nPresione Enter para continuar...")

def block_ip():
    """Bloquea una dirección IP específica"""
    print(f"\n{Colors.BLUE}=== Bloquear dirección IP ==={Colors.ENDC}")
    ip = get_input("Ingrese la dirección IP a bloquear (ej. 192.168.1.100 o 10.0.0.0/24): ", 
                  validate_ip, 
                  "Dirección IP inválida. Use el formato xxx.xxx.xxx.xxx o xxx.xxx.xxx.xxx/xx")
    
    # Confirmación
    confirm = input(f"¿Está seguro de que desea bloquear {ip}? (s/n): ").lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    
    command = f"iptables -A INPUT -s {ip} -j DROP"
    if execute_command(command) is not None:
        print(f"{Colors.GREEN}IP {ip} bloqueada exitosamente.{Colors.ENDC}")
        log_action(f"Bloqueada IP: {ip}")
    
    input("\nPresione Enter para continuar...")

def block_port():
    """Bloquea un puerto específico"""
    print(f"\n{Colors.BLUE}=== Bloquear puerto ==={Colors.ENDC}")
    port = get_input("Ingrese el puerto a bloquear (1-65535): ", 
                    validate_port, 
                    "Puerto inválido. Debe ser un número entre 1 y 65535.")
    
    protocol = get_input("¿Qué protocolo desea bloquear? (tcp/udp/both): ",
                        lambda x: x.lower() in ['tcp', 'udp', 'both'],
                        "Protocolo inválido. Use 'tcp', 'udp' o 'both'.")
    
    # Confirmación
    confirm = input(f"¿Está seguro de que desea bloquear el puerto {port}/{protocol}? (s/n): ").lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    
    if protocol == 'both':
        cmd_tcp = f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        cmd_udp = f"iptables -A INPUT -p udp --dport {port} -j DROP"

        success_tcp = execute_command(cmd_tcp) is not None
        success_udp = execute_command(cmd_udp) is not None

        if success_tcp and success_udp:
            print(f"{Colors.GREEN}Puerto {port} (TCP y UDP) bloqueado exitosamente.{Colors.ENDC}")
            log_action(f"Bloqueado puerto {port} (TCP y UDP)")
    else:
        cmd = f"iptables -A INPUT -p {protocol} --dport {port} -j DROP"
        if execute_command(cmd) is not None:
            print(f"{Colors.GREEN}Puerto {port}/{protocol} bloqueado exitosamente.{Colors.ENDC}")
            log_action(f"Bloqueado puerto {port}/{protocol}")
    
    input("\nPresione Enter para continuar...")

def allow_port():
    """Permite tráfico en un puerto específico"""
    print(f"\n{Colors.BLUE}=== Permitir puerto ==={Colors.ENDC}")
    port = get_input("Ingrese el puerto a permitir (1-65535): ", 
                    validate_port, 
                    "Puerto inválido. Debe ser un número entre 1 y 65535.")
    
    protocol = get_input("¿Qué protocolo desea permitir? (tcp/udp/both): ",
                        lambda x: x.lower() in ['tcp', 'udp', 'both'],
                        "Protocolo inválido. Use 'tcp', 'udp' o 'both'.")
    
    # Confirmación
    confirm = input(f"¿Está seguro de que desea permitir el puerto {port}/{protocol}? (s/n): ").lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    
    if protocol == 'both':
        cmd_tcp = f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT"
        cmd_udp = f"iptables -A INPUT -p udp --dport {port} -j ACCEPT"

        success_tcp = execute_command(cmd_tcp) is not None
        success_udp = execute_command(cmd_udp) is not None

        if success_tcp and success_udp:
            print(f"{Colors.GREEN}Puerto {port} (TCP y UDP) permitido exitosamente.{Colors.ENDC}")
            log_action(f"Permitido puerto {port} (TCP y UDP)")
    else:
        cmd = f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT"
        if execute_command(cmd) is not None:
            print(f"{Colors.GREEN}Puerto {port}/{protocol} permitido exitosamente.{Colors.ENDC}")
            log_action(f"Permitido puerto {port}/{protocol}")
    
    input("\nPresione Enter para continuar...")

def reset_firewall():
    """Elimina todas las reglas del firewall"""
    print(f"\n{Colors.BLUE}=== Restablecer firewall ==={Colors.ENDC}")
    print(f"{Colors.WARNING}ADVERTENCIA: Esta acción eliminará TODAS las reglas actuales del firewall.{Colors.ENDC}")
    print(f"{Colors.WARNING}Si está conectado remotamente, podría perder el acceso al sistema.{Colors.ENDC}")
    
    confirm = input(f"¿Está SEGURO de que desea eliminar todas las reglas? (escriba 'CONFIRMAR' para proceder): ")
    if confirm != 'CONFIRMAR':
        print("Operación cancelada.")
        return
    
    # Comandos para limpiar todas las reglas
    commands = [
        "iptables -F",  # Flush all rules
        "iptables -X",  # Delete all user-defined chains
        "iptables -t nat -F",  # Flush nat table
        "iptables -t nat -X",  # Delete user-defined chains in nat table
        "iptables -t mangle -F",  # Flush mangle table
        "iptables -t mangle -X",  # Delete user-defined chains in mangle table
        "iptables -P INPUT ACCEPT",  # Set default policies to ACCEPT
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT ACCEPT"
    ]
    
    success = True
    for cmd in commands:
        if execute_command(cmd) is None:
            success = False
            break
    
    if success:
        print(f"{Colors.GREEN}Firewall restablecido exitosamente. Todas las reglas han sido eliminadas.{Colors.ENDC}")
        log_action("Firewall restablecido - Todas las reglas eliminadas")
    else:
        print(f"{Colors.FAIL}Error al restablecer el firewall.{Colors.ENDC}")
    
    input("\nPresione Enter para continuar...")

def save_configuration():
    """Guarda la configuración actual en un archivo de restauración"""
    print(f"\n{Colors.BLUE}=== Guardar configuración ==={Colors.ENDC}")
    
    # Obtener reglas actuales
    rules = execute_command("iptables-save")
    if not rules:
        print(f"{Colors.FAIL}Error al obtener las reglas actuales.{Colors.ENDC}")
        input("\nPresione Enter para continuar...")
        return
    
    # Crear script de restauración
    with open(RESTORE_FILE, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("# Script de restauración del firewall\n")
        f.write(f"# Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("# Primero limpiamos todas las reglas existentes\n")
        f.write("iptables -F\n")
        f.write("iptables -X\n")
        f.write("iptables -t nat -F\n")
        f.write("iptables -t nat -X\n")
        f.write("iptables -t mangle -F\n")
        f.write("iptables -t mangle -X\n\n")
        f.write("# Restauramos las reglas guardadas\n")
        f.write("iptables-restore << 'EOF'\n")
        f.write(rules)
        f.write("EOF\n")
        f.write("\necho 'Reglas de firewall restauradas exitosamente.'\n")
    
    # Hacer el script ejecutable
    execute_command(f"chmod +x {RESTORE_FILE}")
    
    print(f"{Colors.GREEN}Configuración guardada en {RESTORE_FILE}{Colors.ENDC}")
    print(f"Para restaurar esta configuración, ejecute: {Colors.BOLD}sudo bash {RESTORE_FILE}{Colors.ENDC}")
    log_action(f"Configuración guardada en {RESTORE_FILE}")
    
    input("\nPresione Enter para continuar...")

def secure_mode():
    """Activa el modo seguro: bloquea todo excepto HTTP/HTTPS y opcionalmente SSH"""
    print(f"\n{Colors.BLUE}=== Activar modo seguro ==={Colors.ENDC}")
    print("El modo seguro bloqueará todo el tráfico entrante excepto:")
    print("  - HTTP (puerto 80)")
    print("  - HTTPS (puerto 443)")
    print("  - Conexiones establecidas y relacionadas")
    
    confirm = input(
        f"\n{Colors.WARNING}ADVERTENCIA: Si está conectado por SSH, puede perder el acceso.{Colors.ENDC}\n¿Desea continuar? (s/n): "
    ).lower()
    if confirm != 's':
        print("Operación cancelada.")
        return

    allow_ssh = input("¿Desea permitir SSH (puerto 22)? (s/n): ").lower() == 's'

    # Lista de comandos para configurar el modo seguro
    commands = [
        "iptables -F",  # Limpia reglas existentes
        "iptables -X",  # Elimina cadenas personalizadas
        "iptables -P INPUT DROP",  # Política predeterminada: DROP para entrada
        "iptables -P FORWARD DROP",  # Política predeterminada: DROP para reenvío
        "iptables -P OUTPUT ACCEPT",  # Política predeterminada: ACCEPT para salida

        # Permitir conexiones establecidas y relacionadas
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",

        # Permitir interfaz de loopback
        "iptables -A INPUT -i lo -j ACCEPT",

        # Permitir HTTP y HTTPS
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",

        # Registrar paquetes descartados para análisis
        "iptables -A INPUT -j LOG --log-prefix 'IPTables-Dropped: ' --log-level 4",
    ]

    if allow_ssh:
        commands.insert(7, "iptables -A INPUT -p tcp --dport 22 -j ACCEPT")
    
    success = True
    for cmd in commands:
        if execute_command(cmd) is None:
            success = False
            break
    
    if success:
        print(f"{Colors.GREEN}Modo seguro activado exitosamente.{Colors.ENDC}")
        allowed = "HTTP (80) y HTTPS (443)"
        if allow_ssh:
            allowed += " y SSH (22)"
        print(f"Sólo se permite tráfico {allowed}.")
        log_action("Modo seguro activado")
    else:
        print(f"{Colors.FAIL}Error al activar el modo seguro.{Colors.ENDC}")
    
    input("\nPresione Enter para continuar...")

def allow_trusted_ip():
    """Permite acceso a una IP confiable"""
    print(f"\n{Colors.BLUE}=== Permitir IP confiable ==={Colors.ENDC}")
    
    ip = get_input("Ingrese la dirección IP confiable a permitir: ", 
                  validate_ip, 
                  "Dirección IP inválida. Use el formato xxx.xxx.xxx.xxx o xxx.xxx.xxx.xxx/xx")
    
    services = {
        '1': {'name': 'SSH', 'port': 22, 'protocol': 'tcp'},
        '2': {'name': 'HTTP', 'port': 80, 'protocol': 'tcp'},
        '3': {'name': 'HTTPS', 'port': 443, 'protocol': 'tcp'},
        '4': {'name': 'DNS', 'port': 53, 'protocol': 'both'},
        '5': {'name': 'FTP', 'port': 21, 'protocol': 'tcp'},
        '6': {'name': 'SMTP', 'port': 25, 'protocol': 'tcp'},
        '7': {'name': 'POP3', 'port': 110, 'protocol': 'tcp'},
        '8': {'name': 'IMAP', 'port': 143, 'protocol': 'tcp'},
        '9': {'name': 'Todo el tráfico', 'port': None, 'protocol': None}
    }
    
    print("\nSeleccione el servicio a permitir para esta IP:")
    for key, service in services.items():
        print(f"{key}. {service['name']}")
    
    option = get_input("\nOpción: ", lambda x: x in services.keys(), "Opción inválida")
    selected = services[option]
    
    # Confirmación
    service_desc = "todo el tráfico" if selected['port'] is None else f"{selected['name']} (puerto {selected['port']})"
    confirm = input(f"¿Está seguro de permitir {service_desc} desde {ip}? (s/n): ").lower()
    if confirm != 's':
        print("Operación cancelada.")
        return
    
    if selected['port'] is None:
        # Permitir todo el tráfico desde esta IP
        cmd = f"iptables -A INPUT -s {ip} -j ACCEPT"
        if execute_command(cmd) is not None:
            print(f"{Colors.GREEN}Se ha permitido todo el tráfico desde {ip}{Colors.ENDC}")
            log_action(f"Permitido todo el tráfico desde IP: {ip}")
    else:
        # Permitir tráfico específico
        if selected['protocol'] == 'both':
            cmd_tcp = f"iptables -A INPUT -s {ip} -p tcp --dport {selected['port']} -j ACCEPT"
            cmd_udp = f"iptables -A INPUT -s {ip} -p udp --dport {selected['port']} -j ACCEPT"

            success_tcp = execute_command(cmd_tcp) is not None
            success_udp = execute_command(cmd_udp) is not None

            if success_tcp and success_udp:
                print(f"{Colors.GREEN}Se ha permitido {selected['name']} (puerto {selected['port']}) desde {ip}{Colors.ENDC}")
                log_action(f"Permitido {selected['name']} desde IP: {ip}")
        else:
            cmd = f"iptables -A INPUT -s {ip} -p {selected['protocol']} --dport {selected['port']} -j ACCEPT"
            if execute_command(cmd) is not None:
                print(f"{Colors.GREEN}Se ha permitido {selected['name']} (puerto {selected['port']}) desde {ip}{Colors.ENDC}")
                log_action(f"Permitido {selected['name']} desde IP: {ip}")
    
    input("\nPresione Enter para continuar...")

def basic_firewall():
    """Configura reglas básicas de firewall"""
    print(f"\n{Colors.BLUE}=== Activar firewall básico ==={Colors.ENDC}")
    confirm = input("Esto reemplazará las reglas actuales. ¿Desea continuar? (s/n): ").lower()
    if confirm != 's':
        print("Operación cancelada.")
        return

    commands = [
        "iptables -F",
        "iptables -X",
        "iptables -P INPUT DROP",
        "iptables -P FORWARD DROP",
        "iptables -P OUTPUT ACCEPT",
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -i lo -j ACCEPT",
        "iptables -A INPUT -p icmp -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
        "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
        "iptables -A INPUT -j LOG --log-prefix 'IPTables-Basic: ' --log-level 4",
    ]

    success = True
    for cmd in commands:
        if not execute_command(cmd):
            success = False
            break

    if success:
        print(f"{Colors.GREEN}Firewall básico activado.{Colors.ENDC}")
        log_action("Firewall básico activado")
    else:
        print(f"{Colors.FAIL}Error al aplicar el firewall básico.{Colors.ENDC}")

    input("\nPresione Enter para continuar...")

def handle_sigint(sig, frame):
    """Maneja la interrupción CTRL+C limpiamente"""
    print("\n\nSaliendo del programa...")
    log_action("Programa cerrado por el usuario (SIGINT)")
    sys.exit(0)

def show_menu():
    """Muestra el menú principal del programa"""
    options = {
        '1': {'text': 'Ver reglas actuales', 'function': show_rules},
        '2': {'text': 'Bloquear IP', 'function': block_ip},
        '3': {'text': 'Bloquear puerto', 'function': block_port},
        '4': {'text': 'Permitir puerto', 'function': allow_port},
        '5': {'text': 'Permitir IP confiable', 'function': allow_trusted_ip},
        '6': {'text': 'Activar modo seguro (HTTP/HTTPS/SSH)', 'function': secure_mode},
        '7': {'text': 'Restablecer firewall (eliminar todas las reglas)', 'function': reset_firewall},
        '8': {'text': 'Guardar configuración', 'function': save_configuration},
        '9': {'text': 'Activar firewall básico', 'function': basic_firewall},
        '0': {'text': 'Salir', 'function': None}
    }
    
    while True:
        show_banner()
        print(f"{Colors.BLUE}Menú Principal:{Colors.ENDC}")
        
        for key, option in options.items():
            print(f"{key}. {option['text']}")
        
        choice = input(f"\n{Colors.BOLD}Seleccione una opción: {Colors.ENDC}")
        
        if choice == '0':
            print("Gracias por usar Firewall Manager. ¡Hasta pronto!")
            log_action("Programa cerrado normalmente")
            break
        elif choice in options:
            options[choice]['function']()
        else:
            print(f"{Colors.FAIL}Opción inválida. Intente de nuevo.{Colors.ENDC}")
            time.sleep(1)

def main():
    """Función principal del programa"""
    # Registrar manejador para CTRL+C
    signal.signal(signal.SIGINT, handle_sigint)
    
    try:
        # Verificar privilegios de root y dependencias
        check_root()
        check_dependencies()
        
        # Inicializar archivo de log si no existe
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Firewall Manager iniciado\n")
        
        # Mostrar menú principal
        log_action("Programa iniciado")
        show_menu()
        
    except Exception as e:
        print(f"{Colors.FAIL}Error inesperado: {e}{Colors.ENDC}")
        log_action(f"Error inesperado: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())