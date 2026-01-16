# ¿Qué es Linux?
Linux es un sistema operativo de código abierto basado en Unix, creado por Linus Torvalds en 1991. Es el núcleo (kernel) que gestiona los recursos del hardware y permite que el software se ejecute en la computadora. Linux es gratuito, altamente personalizable y es la base de muchos sistemas operativos utilizados en servidores, dispositivos móviles, supercomputadoras y dispositivos integrados.

## Conceptos Fundamentales
### Kernel
El núcleo del sistema operativo que gestiona la comunicación entre el hardware y el software.
### Shell
Interfaz de línea de comandos que permite a los usuarios interactuar con el sistema operativo.
### Distribución (Distro)
Combinación del kernel de Linux con herramientas, aplicaciones y gestores de paquetes que forman un sistema operativo completo.

## Beneficios de Linux
### 1. **Seguridad**
- Menos vulnerable a virus y malware
- Sistema de permisos robusto
- Actualizaciones de seguridad frecuentes
- Comunidad activa que identifica y corrige vulnerabilidades rápidamente
### 2. **Estabilidad y Rendimiento**
- Puede funcionar durante años sin necesidad de reiniciar
- Excelente gestión de recursos
- Ideal para servidores y aplicaciones críticas
- Menor consumo de recursos que otros sistemas operativos
### 3. **Personalización**
- Completamente configurable según necesidades
- Múltiples entornos de escritorio disponibles
- Flexibilidad para adaptar el sistema

## Distribuciones de Linux
### **Ubuntu**
- La distribución más popular y amigable para principiantes
- Basada en Debian
- Gran comunidad y soporte
- Actualizaciones cada 6 meses
- Ideal para: Usuarios nuevos, escritorio, servidores
### **Debian**
- Una de las distribuciones más antiguas y estables
- Base de muchas otras distribuciones (Ubuntu, Mint, etc.)
- Muy estable pero software menos actualizado
- Ideal para: Servidores, usuarios que priorizan estabilidad
### **Arch Linux**
- Distribución minimalista y personalizable
- Rolling release
- Requiere instalación manual
- Documentación excelente (Arch Wiki)
- Ideal para: Usuarios avanzados, aprendizaje profundo del sistema
### **Ubuntu Server**
- Versión de Ubuntu para servidores
- Amplio soporte de hardware
- Actualizaciones LTS (Long Term Support)
- Ideal para: Servidores cloud, infraestructura

## Infraestructura en la nube
### VPS (Servidor Privado Virtual)
- Un VPS es una partición virtualizada de un servidor físico que actúa como un servidor dedicado.
- Permite a los usuarios tener control total sobre su entorno de servidor sin necesidad de compartir recursos con otros usuarios.
- Ideal para alojar sitios web, aplicaciones y servicios en línea.
- Ofrece flexibilidad, escalabilidad y costos más bajos en comparación con servidores dedicados.
### VPC (Virtual Private Cloud)
- Una VPC es una red privada virtual dentro de un entorno de nube pública.
- Permite a los usuarios crear y gestionar su propia red aislada, con control sobre la configuración de subredes, tablas de rutas y gateways.
- Ideal para ejecutar aplicaciones y servicios en un entorno seguro y escalable.
### VPS vs VPC
- Un VPS es un servidor virtualizado, mientras que una VPC es una red virtualizada.
- Un VPS se utiliza para alojar aplicaciones y servicios, mientras que una VPC se utiliza para gestionar la conectividad y seguridad de esos servicios en la nube.
- Ambos ofrecen flexibilidad y control, pero en diferentes niveles de la infraestructura de TI.

## Tecnologías y Herramientas Esenciales para VPS

### SSH (Secure Shell)
- Protocolo de red criptográfico para comunicación segura entre cliente y servidor
- Permite acceso remoto a servidores de forma cifrada y segura
- Soporta autenticación por contraseña o por claves públicas/privadas (más seguro)
- Usado para administración remota, transferencia segura de archivos (SCP) y túneles seguros
- Puerto por defecto: 22 (recomendado cambiarlo por seguridad)

### Nginx
- Servidor web de alto rendimiento, ligero y eficiente
- Puede funcionar como servidor web, proxy inverso, balanceador de carga y caché HTTP
- Diseñado para manejar miles de conexiones simultáneas con bajo consumo de recursos
- Arquitectura asíncrona y orientada a eventos (más eficiente que Apache en muchos casos)
- Ideal para servir sitios estáticos, aplicaciones web y APIs

### MySQL
- Sistema de gestión de bases de datos relacional (RDBMS) open source
- Utiliza SQL (Structured Query Language) para consultas y manipulación de datos
- Ampliamente usado en aplicaciones web (WordPress, aplicaciones PHP, etc.)
- Soporta transacciones ACID, replicación y clustering
- Alternativas: MariaDB (fork de MySQL), PostgreSQL

### UFW (Uncomplicated Firewall)
- Interfaz simplificada para gestionar iptables en Linux
- Firewall de aplicación que controla tráfico entrante y saliente
- Permite crear reglas fácilmente para permitir/denegar puertos y servicios
- Esencial para seguridad del servidor: bloquea accesos no autorizados
- Configuración por defecto: denegar todo entrante, permitir todo saliente

### Fail2ban
- Sistema de prevención de intrusiones (IPS) que protege contra ataques de fuerza bruta
- Monitorea logs del sistema en busca de patrones de intentos fallidos de autenticación
- Banea automáticamente IPs sospechosas mediante reglas de firewall temporales
- Protege servicios como SSH, Nginx, Apache, FTP, etc.
- Configurable mediante "jails" (prisiones) para diferentes servicios

### Certbot / Let's Encrypt
- Let's Encrypt: Autoridad de certificación gratuita y automatizada que emite certificados SSL/TLS
- Certbot: Cliente oficial para obtener y renovar certificados de Let's Encrypt automáticamente
- Habilita HTTPS en sitios web sin costo
- Certificados válidos por 90 días con renovación automática
- Soporta validación mediante HTTP, DNS y TLS-ALPN

### Systemd / Systemctl
- Systemd: Sistema de inicialización y gestor de servicios moderno para Linux
- Systemctl: Herramienta de línea de comandos para controlar systemd
- Gestiona inicio, detención, reinicio y monitoreo de servicios del sistema
- Permite configurar servicios para inicio automático al arrancar el servidor
- Journalctl: Herramienta complementaria para ver logs centralizados de servicios

### APT (Advanced Package Tool)
- Sistema de gestión de paquetes para distribuciones basadas en Debian/Ubuntu
- Permite instalar, actualizar y eliminar software de repositorios oficiales
- Maneja automáticamente dependencias entre paquetes
- Mantiene el sistema actualizado con parches de seguridad
- Alternativas: YUM/DNF (Red Hat/CentOS), Pacman (Arch Linux)

### SSL/TLS y HTTPS
- SSL (Secure Sockets Layer) / TLS (Transport Layer Security): Protocolos criptográficos para comunicación segura
- HTTPS: HTTP sobre TLS/SSL que cifra la comunicación entre navegador y servidor
- Protege datos sensibles (contraseñas, tarjetas de crédito, información personal)
- Mejora SEO y confianza de usuarios (Google prioriza sitios HTTPS)
- Requerido para APIs modernas, PWAs y muchas funcionalidades del navegador

### DNS (Domain Name System)
- Sistema que traduce nombres de dominio legibles (ejemplo.com) a direcciones IP (192.168.1.1)
- Permite acceder a sitios web usando nombres en lugar de números
- Tipos de registros DNS:
  - **A (Address)**: Mapea dominio a dirección IPv4. Ejemplo: `ejemplo.com → 192.168.1.100`
  - **AAAA (IPv6 Address)**: Mapea dominio a dirección IPv6. Ejemplo: `ejemplo.com → 2001:0db8::1`
  - **CNAME (Canonical Name)**: Crea alias apuntando a otro dominio. Ejemplo: `www.ejemplo.com → ejemplo.com`
  - **MX (Mail Exchange)**: Define servidores de correo para el dominio. Ejemplo: `ejemplo.com → mail.ejemplo.com (prioridad 10)`
  - **TXT (Text)**: Almacena texto arbitrario, usado para verificación y SPF. Ejemplo: `"v=spf1 include:_spf.google.com ~all"`
  - **NS (Name Server)**: Especifica servidores DNS autoritativos. Ejemplo: `ejemplo.com → ns1.cloudflare.com`
  - **SOA (Start of Authority)**: Información administrativa de la zona DNS (servidor primario, email contacto, TTL)
- Propagación DNS puede tomar de minutos a 48 horas después de cambios
- Proveedores populares: Cloudflare, Route 53 (AWS), Google Cloud DNS
- TTL (Time To Live): Tiempo que un registro DNS es cacheado por servidores antes de refrescarse

### Proxy Inverso (Reverse Proxy)
- Servidor intermediario que recibe peticiones de clientes y las reenvía a servidores backend
- Oculta la arquitectura interna del servidor y protege servidores de aplicación
- Beneficios: balanceo de carga, caché, compresión, terminación SSL
- Permite servir múltiples aplicaciones/dominios desde una misma IP
- Nginx y Apache son proxies inversos populares

### Permisos y Usuarios en Linux
- Sistema de permisos basado en propietario, grupo y otros
- Tres tipos de permisos: lectura (r), escritura (w), ejecución (x)
- Notación numérica: 7=rwx, 6=rw-, 5=r-x, 4=r--, 3=-wx, 2=-w-, 1=--x, 0=---
- Usuarios y grupos permiten control granular de acceso a recursos
- Principio de mínimo privilegio: dar solo los permisos necesarios

### Cron / Crontab
- Sistema de programación de tareas automatizadas en Unix/Linux
- Ejecuta comandos o scripts en horarios específicos (diario, semanal, mensual)
- Sintaxis: minuto hora día mes día_semana comando
- Usado para backups automáticos, limpieza de logs, renovación de certificados
- Alternativas modernas: systemd timers

### Logs y Monitoreo
- Logs: Archivos de registro que documentan eventos y actividades del sistema
- Ubicación común: /var/log/ (syslog, auth.log, nginx, mysql, etc.)
- Journald (systemd): Sistema centralizado de logs binarios
- Esenciales para debugging, auditoría de seguridad y análisis de rendimiento
- Herramientas: tail -f (tiempo real), grep (búsqueda), journalctl (systemd)

### Procesos en Linux
- Proceso: Programa en ejecución con su propio espacio de memoria
- PID (Process ID): Identificador único de cada proceso
- Estados: running, sleeping, stopped, zombie
- Prioridad (nice): -20 (máxima) a 19 (mínima), default 0
- Señales: SIGTERM (15, cierre limpio), SIGKILL (9, cierre forzado)

### Snap / Snapd
- Sistema de paquetes universal desarrollado por Canonical (Ubuntu)
- Paquetes autocontenidos con todas sus dependencias incluidas
- Actualizaciones automáticas y aislamiento de seguridad (confinement)
- Funciona en múltiples distribuciones Linux
- Usado para instalar software moderno como Certbot, Docker, VS Code

### Git / Control de Versiones
- Sistema de control de versiones distribuido para rastrear cambios en código
- Permite colaboración entre múltiples desarrolladores
- Conceptos clave: repositorio, commit, branch, merge, pull, push
- Plataformas: GitHub, GitLab, Bitbucket
- Esencial para deployment continuo y gestión de configuraciones de servidor

### HTTP/1.1 vs HTTP/2
- **HTTP/1.1** (1997): Una conexión TCP por recurso, solicitudes secuenciales
- **HTTP/2** (2015): Multiplexado - múltiples solicitudes simultáneas en una sola conexión TCP
- Diferencias principales:
  - **Multiplexing**: HTTP/2 permite enviar múltiples archivos en paralelo; HTTP/1.1 debe esperar respuesta antes de siguiente solicitud
  - **Server Push**: HTTP/2 puede enviar recursos antes de que el cliente los solicite
  - **Compresión de headers**: HTTP/2 comprime encabezados, HTTP/1.1 no
  - **Binario vs Texto**: HTTP/2 usa protocolo binario (más rápido), HTTP/1.1 usa texto plano
  - **Rendimiento**: HTTP/2 es 30-50% más rápido en promedio
- Ambos usan los mismos métodos: GET, POST, PUT, DELETE, etc.

### Docker / Contenedores
- Plataforma para crear, desplegar y ejecutar aplicaciones en contenedores
- Contenedor: Paquete ligero que incluye aplicación + todas sus dependencias
- Diferencia con VM: Comparte kernel del host, más ligero y rápido de iniciar
- Beneficios: portabilidad, aislamiento, consistencia entre entornos (dev, staging, prod)
- Dockerfile: Archivo que define cómo construir una imagen
- Docker Hub: Repositorio público de imágenes pre-construidas

### API REST (Representational State Transfer)
- Arquitectura para servicios web que usa HTTP para comunicación
- Basado en recursos identificados por URLs (endpoints)
- Métodos HTTP estándar: GET (leer), POST (crear), PUT/PATCH (actualizar), DELETE (eliminar)
- Stateless: Cada petición es independiente, sin sesión en el servidor
- Respuestas típicas en JSON o XML
- Ejemplo: `GET /api/users/123` obtiene información del usuario con ID 123

### CDN (Content Delivery Network)
- Red distribuida de servidores que entregan contenido a usuarios desde ubicaciones geográficamente cercanas
- Reduce latencia al servir archivos desde servidor más próximo al usuario
- Cachea contenido estático: imágenes, CSS, JavaScript, videos
- Beneficios: mayor velocidad, reducción de carga en servidor origen, mejor disponibilidad
- Proveedores populares: Cloudflare, AWS CloudFront, Fastly, Akamai
- Especialmente útil para sitios con audiencia global

### Cloudflare
- Plataforma integral de seguridad, rendimiento y confiabilidad para sitios web y aplicaciones
- **Servicios principales:**
  - **CDN Global**: Red de 300+ centros de datos para entregar contenido rápidamente
  - **DNS Gratuito**: Uno de los DNS más rápidos del mundo (1.1.1.1)
  - **Protección DDoS**: Mitiga ataques distribuidos de denegación de servicio automáticamente
  - **WAF (Web Application Firewall)**: Protege contra vulnerabilidades web (SQL injection, XSS, etc.)
  - **SSL/TLS Gratuito**: Certificados SSL automáticos con opción Flexible, Full o Full (Strict)
  - **Bot Management**: Bloquea bots maliciosos, permite bots buenos (Google, etc.)
  - **Page Rules**: Configuración personalizada por URL (caché, redirecciones, seguridad)
  - **Workers**: Serverless computing en el edge para lógica personalizada
  - **Zero Trust**: Soluciones de acceso seguro (VPN, autenticación)
- **Modos de cifrado SSL/TLS:**
  - **Off**: Sin cifrado (no recomendado)
  - **Flexible**: Cifrado navegador↔Cloudflare, HTTP Cloudflare↔origen (no seguro)
  - **Full**: Cifrado navegador↔Cloudflare↔origen, acepta certificados auto-firmados
  - **Full (Strict)**: Cifrado completo con certificado válido en origen (recomendado)
- **Ventajas:**
  - Plan gratuito generoso para sitios personales y pequeños
  - Mejora rendimiento automático (HTTP/2, HTTP/3, Brotli, minificación)
  - Analíticas detalladas de tráfico y amenazas
  - Oculta IP real del servidor origen (protección adicional)
  - Caché inteligente configurable con purga manual o automática
- **Limitaciones del plan gratuito:**
  - Sin soporte por email/chat (solo comunidad)
  - Page Rules limitadas (3)
  - Sin configuración avanzada de WAF
  - Certificados SSL compartidos
- **Integración con VPS:**
  - Configurar nameservers en registrador de dominio apuntando a Cloudflare
  - Crear registros DNS (A, AAAA, CNAME) en Cloudflare dashboard
  - Activar proxy (nube naranja) para protección o DNS-only (nube gris) para bypass
  - Configurar Nginx/Apache en VPS para reconocer IPs reales (mod_cloudflare, real_ip)
  - Origin Certificate gratuito de Cloudflare para SSL Full (Strict)
- Alternativas: Fastly, AWS CloudFront, Akamai (más caros, enfoque empresarial)

### Balanceador de Carga (Load Balancer)
- Distribuye tráfico entrante entre múltiples servidores backend
- Evita sobrecarga de un solo servidor y mejora disponibilidad
- Algoritmos comunes: Round Robin, Least Connections, IP Hash
- Puede detectar servidores caídos y redirigir tráfico a servidores saludables
- Tipos: Layer 4 (TCP/UDP) o Layer 7 (HTTP/HTTPS)
- Nginx, HAProxy y AWS ELB son balanceadores populares

### Caché / Caching
- Almacenamiento temporal de datos frecuentemente accedidos para respuesta rápida
- Niveles: Browser cache, CDN cache, Server cache, Database cache
- Reduce carga en base de datos y servidor backend
- Headers HTTP para control: Cache-Control, ETag, Expires
- Tecnologías: Redis, Memcached, Varnish
- Trade-off: velocidad vs frescura de datos

### Backup y Snapshot
- **Backup**: Copia completa de datos para recuperación ante desastres
- **Snapshot**: Imagen del estado del sistema en un momento específico
- Diferencias:
  - Snapshot es instantáneo, backup puede tomar tiempo
  - Snapshot ocupa menos espacio inicial (incremental)
  - Backup es copia completa independiente
- Estrategia 3-2-1: 3 copias, 2 tipos de medio, 1 offsite
- Automatizar backups con cron o herramientas cloud

### Puertos (Ports)
- Número de 16 bits (0-65535) que identifica un servicio específico en un servidor
- Permiten múltiples servicios en una misma IP
- Rangos:
  - **0-1023**: Puertos bien conocidos (Well-known) - Requieren privilegios root
  - **1024-49151**: Puertos registrados - Asignados por IANA
  - **49152-65535**: Puertos dinámicos/privados - Uso temporal
- Puertos comunes: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL), 5432 (PostgreSQL)
- Firewall controla qué puertos están abiertos/cerrados

### IPv4 vs IPv6
- **IPv4**: Formato de 32 bits (4.3 mil millones de direcciones). Ejemplo: `192.168.1.1`
- **IPv6**: Formato de 128 bits (340 undecillones de direcciones). Ejemplo: `2001:0db8:85a3::8a2e:0370:7334`
- Razón del cambio: IPv4 se está agotando
- Ventajas IPv6: más direcciones, autoconfiguración, seguridad mejorada (IPsec obligatorio)
- Transición lenta: Muchos servicios aún solo IPv4, dual-stack es común
- NAT (Network Address Translation) extiende vida de IPv4 pero IPv6 es el futuro

### WebSocket
- Protocolo de comunicación bidireccional en tiempo real sobre una sola conexión TCP
- Diferencia con HTTP: Conexión persistente vs solicitud/respuesta
- Casos de uso: chat en vivo, notificaciones push, juegos multijugador, dashboards en tiempo real
- Inicia con handshake HTTP, luego se actualiza a WebSocket
- Puertos: Usa 80 (ws://) o 443 (wss:// para seguro)
- Más eficiente que polling para actualizaciones frecuentes

## Estructura de Directorios en Linux (Filesystem Hierarchy Standard)

### /etc/ (System Configuration)
- Directorio de configuración del sistema y aplicaciones
- "etc" originalmente significaba "etcetera", ahora "Editable Text Configuration"
- Contiene archivos de configuración en texto plano (sin binarios)
- Requiere privilegios root para modificar archivos
- Subdirectorios importantes:
  - **/etc/nginx/**: Configuración de Nginx (nginx.conf, sites-available/, sites-enabled/)
  - **/etc/apache2/**: Configuración de Apache web server
  - **/etc/php/**: Configuración de PHP por versión (php.ini, php-fpm.conf)
  - **/etc/mysql/**: Configuración de MySQL/MariaDB (my.cnf)
  - **/etc/ssh/**: Configuración del servidor SSH (sshd_config)
  - **/etc/fail2ban/**: Configuración de Fail2ban (jail.conf, jail.local)
  - **/etc/systemd/**: Configuración de systemd y servicios
  - **/etc/cron.d/**: Tareas programadas del sistema
  - **/etc/hosts**: Mapeo local de nombres de dominio a IPs
  - **/etc/fstab**: Configuración de montaje de discos al arrancar

### /var/ (Variable Data)
- Datos variables que cambian durante operación del sistema
- Archivos que crecen o se modifican frecuentemente
- Logs, bases de datos, cachés, colas de correo, archivos temporales
- Subdirectorios principales:
  - **/var/log/**: Archivos de registro (logs) del sistema y aplicaciones
  - **/var/www/**: Directorio por defecto para sitios web (Nginx, Apache)
  - **/var/lib/**: Datos persistentes de aplicaciones (bases de datos)
  - **/var/cache/**: Cachés de aplicaciones
  - **/var/tmp/**: Archivos temporales que persisten entre reinicios
  - **/var/mail/**: Buzones de correo de usuarios

### /var/log/ (System & Application Logs)
- Todos los archivos de registro del sistema
- Esencial para debugging, monitoreo y auditoría de seguridad
- Logs importantes:
  - **/var/log/syslog**: Log general del sistema (Ubuntu/Debian)
  - **/var/log/auth.log**: Intentos de autenticación y accesos SSH
  - **/var/log/nginx/**: Logs de Nginx (access.log, error.log)
  - **/var/log/apache2/**: Logs de Apache web server
  - **/var/log/mysql/**: Logs de MySQL (error.log, slow-query.log)
  - **/var/log/php*-fpm.log**: Logs de PHP-FPM
  - **/var/log/fail2ban.log**: Registro de IPs baneadas por Fail2ban
  - **/var/log/kern.log**: Logs del kernel de Linux
- Rotación automática con logrotate para evitar llenar disco

### /var/www/ (Web Root Directory)
- Directorio raíz por defecto para contenido web
- Usado por Nginx, Apache y otros servidores web
- Estructura típica:
  - **/var/www/html/**: Sitio web por defecto
  - **/var/www/dominio.com/**: Sitio de un dominio específico
  - **/var/www/dominio.com/public_html/**: Carpeta pública del sitio
- Permisos típicos: usuario del sitio + grupo www-data

### /var/lib/ (Application State Data)
- Datos persistentes de aplicaciones y servicios
- Bases de datos, archivos de estado, información que debe sobrevivir reinicios
- Subdirectorios importantes:
  - **/var/lib/mysql/**: Archivos de base de datos MySQL/MariaDB
  - **/var/lib/postgresql/**: Archivos de base de datos PostgreSQL
  - **/var/lib/docker/**: Imágenes, contenedores y volúmenes de Docker
  - **/var/lib/snapd/**: Paquetes instalados via Snap
  - **/var/lib/apt/**: Estado del gestor de paquetes APT

### /home/ (User Home Directories)
- Directorios personales de cada usuario del sistema
- Cada usuario tiene su espacio privado: /home/usuario/
- Contiene archivos personales, configuraciones de usuario, proyectos
- Subdirectorios comunes:
  - **~/.ssh/**: Claves SSH y configuración (authorized_keys, id_rsa)
  - **~/.config/**: Configuraciones de aplicaciones de usuario
  - **~/.bashrc**: Configuración del shell bash
  - **~/public_html/**: En algunos servidores, sitio web del usuario

### /usr/ (User System Resources)
- Programas y archivos de solo lectura compartidos por usuarios
- Segunda jerarquía más grande después de raíz
- Subdirectorios importantes:
  - **/usr/bin/**: Binarios ejecutables de programas instalados por gestor de paquetes
  - **/usr/sbin/**: Binarios de administración del sistema
  - **/usr/lib/**: Librerías compartidas de programas
  - **/usr/local/**: Software instalado manualmente (no por gestor de paquetes)
  - **/usr/local/bin/**: Ejecutables instalados manualmente (scripts personalizados, programas compilados)
  - **/usr/share/**: Datos compartidos independientes de arquitectura (docs, iconos)

### /opt/ (Optional Software)
- Software opcional o de terceros instalado manualmente
- Aplicaciones comerciales o paquetes grandes
- Cada aplicación en su propio subdirectorio: /opt/aplicacion/
- Ejemplos: /opt/google/chrome/, /opt/lampp/ (XAMPP)

### /tmp/ (Temporary Files)
- Archivos temporales del sistema y aplicaciones
- Se vacía automáticamente al reiniciar (en muchas distribuciones)
- Cualquier usuario puede escribir aquí
- No guardar datos importantes, se borran frecuentemente
- Alternativa: /var/tmp/ (persiste entre reinicios)

### /root/ (Root User Home)
- Directorio home del usuario root (administrador)
- Diferente de / (raíz del sistema)
- Solo accesible por root
- Contiene configuraciones y archivos del superusuario

### /bin/ y /sbin/ (Essential Binaries)
- **/bin/**: Comandos esenciales para todos los usuarios (ls, cp, cat, bash)
- **/sbin/**: Comandos de administración del sistema (reboot, iptables, fdisk)
- En sistemas modernos son enlaces simbólicos a /usr/bin/ y /usr/sbin/

### /dev/ (Device Files)
- Archivos especiales que representan dispositivos de hardware
- Interfaz para comunicarse con hardware
- Ejemplos:
  - **/dev/sda**, **/dev/sdb**: Discos duros
  - **/dev/null**: Dispositivo "agujero negro" (descarta todo)
  - **/dev/random**: Generador de números aleatorios
  - **/dev/tty**: Terminales

### /proc/ (Process Information)
- Sistema de archivos virtual (solo existe en RAM)
- Información sobre procesos y kernel en tiempo real
- Ejemplos:
  - **/proc/cpuinfo**: Información del CPU
  - **/proc/meminfo**: Información de memoria
  - **/proc/[PID]/**: Información de proceso específico

### /sys/ (System Information)
- Sistema de archivos virtual para información del kernel
- Interfaz con drivers de dispositivos
- Información de hardware en tiempo real
- Complemento moderno de /proc/

### Rutas específicas por tecnología:

#### PHP:
- **/etc/php/8.1/**: Configuración de PHP 8.1
- **/etc/php/8.1/fpm/**: PHP-FPM (FastCGI Process Manager)
- **/etc/php/8.1/cli/**: PHP para línea de comandos
- **/var/log/php8.1-fpm.log**: Logs de PHP-FPM

#### Java:
- **/usr/lib/jvm/**: Java Virtual Machines instaladas
- **/etc/java-*/**: Configuración de Java
- **/usr/share/java/**: Librerías JAR compartidas

#### Node.js:
- **/usr/bin/node**: Binario de Node.js
- **/usr/lib/node_modules/**: Paquetes npm globales
- **~/.npm/**: Caché de npm (por usuario)

#### Python:
- **/usr/bin/python3**: Binario de Python
- **/usr/lib/python3.*/**: Librerías estándar de Python
- **/usr/local/lib/python3.*/site-packages/**: Paquetes pip

---

Para ver ejemplos de uso específicos de cada comando, consultar el archivo [commands.md](commands.md)

