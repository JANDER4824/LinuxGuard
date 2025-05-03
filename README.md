# LinuxGuard

Un gestor de firewall interactivo para sistemas Linux basado en iptables con enfoque en la seguridad y facilidad de uso.

![License](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)

## 📋 Descripción

LinuxGuard es una herramienta de gestión de firewall para sistemas Linux que proporciona una interfaz de línea de comandos interactiva para administrar reglas de iptables de manera sencilla y segura. El proyecto está diseñado para ayudar a administradores de sistemas y usuarios de Linux a proteger sus servidores y estaciones de trabajo sin necesidad de recordar la sintaxis compleja de iptables.

## ✨ Características

- 🔒 Interfaz interactiva de línea de comandos con menús intuitivos
- 🛡️ Bloqueo de IPs y rangos de red específicos
- 🚫 Bloqueo de puertos TCP/UDP
- ✅ Permitir acceso a IPs confiables para servicios específicos
- 🔥 Modo seguro preconfigurado (HTTP/HTTPS/SSH)
- 💾 Guardado y restauración de configuraciones
- 📊 Registro detallado de todas las acciones
- 🔄 Verificación de requisitos del sistema y módulos del kernel
- 🛡️ Protección contra diversos ataques de red (SYN flood, XMAS, etc.)
- 📌 Soporte para reglas IPv4

## 🔧 Requisitos

- Python 3.6+
- Sistema operativo Linux
- iptables instalado
- Privilegios de root para ejecutar el script

## 📥 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/[tu-usuario]/LinuxGuard.git
cd LinuxGuard

# Hacer el script ejecutable
chmod +x linuxguard.py
```

## 🚀 Uso

```bash
sudo ./linuxguard.py
```

Al iniciar el programa, se mostrará un menú interactivo con las siguientes opciones:

1. Ver reglas actuales
2. Bloquear IP
3. Bloquear puerto
4. Permitir puerto
5. Permitir IP confiable
6. Activar modo seguro (HTTP/HTTPS/SSH)
7. Restablecer firewall (eliminar todas las reglas)
8. Guardar configuración
9. Activar firewall básico
0. Salir

## 🔑 Funcionalidades principales

### Modo seguro

El modo seguro configura rápidamente un conjunto de reglas restrictivas que:
- Permite HTTP (80) y HTTPS (443)
- Opcionalmente mantiene SSH (22) para administración remota
- Bloquea todo el resto del tráfico entrante
- Protege contra ataques comunes de red
- Permite las conexiones ya establecidas

### Restauración de configuración

La función de guardar configuración crea un script de restauración que:
- Limpia todas las reglas existentes
- Restaura exactamente la configuración guardada
- Es ejecutable directamente: `sudo bash restore_rules.sh`

### IP confiables

La función de IP confiables permite:
- Agregar excepciones para IPs específicas
- Permitir acceso a servicios comunes (SSH, HTTP, FTP, etc.)
- Opcionalmente conceder acceso completo a IPs de confianza

## 📝 Archivo de log

El programa mantiene un registro detallado de todas las acciones realizadas en `firewall_log.txt`. Útil para auditoría y diagnóstico.

## ⚠️ Advertencias

- **IMPORTANTE**: Este programa requiere privilegios de root para funcionar correctamente.
- Si está conectado remotamente a través de SSH, tenga cuidado al restablecer las reglas o activar el modo seguro sin permitir SSH.
- Se recomienda guardar la configuración antes de realizar cambios importantes.

## 🛠️ Desarrollo

Este proyecto está abierto a contribuciones. Si desea contribuir:

1. Haga un fork del repositorio
2. Cree una rama para su funcionalidad (`git checkout -b feature/amazing-feature`)
3. Realice sus cambios y commit (`git commit -m 'Add some amazing feature'`)
4. Push a la rama (`git push origin feature/amazing-feature`)
5. Abra un Pull Request

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - vea el archivo [LICENSE](LICENSE) para más detalles.

## 👤 Autor

[JANDER]

---

**Nota**: LinuxGuard es una herramienta de seguridad y debe ser utilizada de forma responsable. El autor no se hace responsable del uso indebido de este software.
