# Comandos Linux para VPS

## Creación y inicializar conexión del Servidor Virtual Privado

ssh: Conectarse de forma segura a un servidor remoto mediante protocolo cifrado
  -p: Especifica el puerto de conexión (default 22)
  usuario@host: Usuario y dirección del servidor
  ssh usuario@192.168.1.100
  ssh root@servidor.com
  ssh -p 2222 usuario@servidor.com

scp: Copiar archivos de forma segura entre local y remoto usando SSH
  -r: Copia directorios de forma recursiva
  origen destino: Especifica ruta local y remota
  scp archivo.txt usuario@servidor.com:/home/usuario/
  scp usuario@servidor.com:/var/log/app.log ./
  scp -r carpeta/ usuario@servidor.com:/backup/

ssh-keygen: Generar par de claves pública/privada para autenticación sin contraseña
  -t: Tipo de algoritmo (rsa, ed25519, ecdsa)
  -C: Comentario para identificar la clave
  ssh-keygen -t rsa
  ssh-keygen -t ed25519 -C "mi@email.com"

eval $(ssh-agent -s): Iniciar el agente SSH para gestionar claves privadas en memoria
  ssh-agent: Programa que mantiene las claves privadas en memoria
  -s: Genera comandos para shell bash/zsh
  eval $(ssh-agent -s)

ssh-add: Agregar clave privada al agente SSH para no pedir contraseña cada vez
  id_rsa: Archivo de clave privada a agregar
  -l: Listar claves agregadas al agente
  ssh-add id_rsa
  ssh-add ~/.ssh/id_ed25519
  ssh-add -l

ssh -T: Probar conexión SSH sin abrir sesión interactiva (solo autenticación)
  -T: Deshabilita asignación de pseudo-terminal
  git@host: Usuario y servidor para probar
  ssh -T git@github.com
  ssh -T git@gitlab.com

## Usando y comprendiendo algunos comandos y tareas esenciales en un VPS

pwd: Mostrar la ruta completa del directorio actual donde te encuentras
  pwd

cd: Cambiar el directorio de trabajo actual
  ..: Sube un nivel (directorio padre)
  /: Ir al directorio raíz
  ~: Ir al directorio home del usuario
  -: Regresar al directorio anterior
  cd /etc/ssh
  cd ..
  cd /
  cd ~
  cd -

ls: Listar contenido de directorios (archivos y carpetas)
  -l: Formato largo con permisos, propietario, tamaño, fecha
  -a: Mostrar archivos ocultos (que empiezan con .)
  -h: Tamaños en formato legible (KB, MB, GB)
  ll: Alias de ls -l
  ls -l
  ll
  ls -a
  ls -la
  ls -lh /var/log

touch: Crear archivo vacío o actualizar fecha de modificación de uno existente
  touch file.txt
  touch archivo1.txt archivo2.txt

mkdir: Crear uno o varios directorios nuevos
  -p: Crea directorios padres si no existen
  mkdir test
  mkdir -p /home/usuario/proyectos/nuevo

cp: Copiar archivos o directorios de un lugar a otro
  -r: Copia directorios de forma recursiva
  -i: Pide confirmación antes de sobrescribir
  origen destino: Especifica archivo fuente y destino
  cp file.txt file2.txt
  cp archivo.txt /home/usuario/backup/
  cp -r test test2
  cp -i file.txt file2.txt

mv: Mover archivos/directorios o renombrarlos
  origen destino: Si destino es diferente mueve, si es mismo directorio renombra
  mv file.txt archivo_renombrado.txt
  mv archivo.txt /home/usuario/documentos/
  mv test2 /

rm: Eliminar archivos o directorios permanentemente
  -r: Elimina directorios y su contenido recursivamente
  -f: Fuerza eliminación sin pedir confirmación
  -rf: Combinación para eliminar todo sin preguntar
  rm file.txt
  rm file*
  rm -r test
  rm -f archivo.txt
  rm -rf /tmp/test2

rmdir: Eliminar solo directorios que estén completamente vacíos
  rmdir carpeta_vacia

find: Buscar archivos y directorios por nombre, tipo, tamaño, fecha
  -name: Buscar por nombre de archivo
  -type f: Buscar solo archivos, -type d solo directorios
  find /home -name "*.txt"
  find . -type f -name "config*"

locate: Buscar archivos rápidamente en base de datos indexada del sistema
  locate archivo.txt

cat: Mostrar todo el contenido de un archivo en pantalla
  cat file.txt
  cat /etc/hosts

nano: Editor de texto simple y fácil de usar en terminal
  Ctrl+O: Guardar, Ctrl+X: Salir
  nano file.txt
  nano /home/usuario/.ssh/authorized_keys

vi/vim: Editor de texto avanzado y potente para terminal
  i: Modo insertar, Esc: Modo comando, :wq: Guardar y salir
  vim config.txt
  vi /etc/ssh/sshd_config

less: Ver archivos largos con navegación (arriba/abajo, buscar)
  Space: Siguiente página, b: Página anterior, q: Salir
  less archivo_largo.txt

more: Visualizar archivos página por página (más básico que less)
  more /var/log/syslog

head: Mostrar las primeras líneas de un archivo (default 10)
  -n: Número de líneas a mostrar
  head archivo.txt
  head -n 20 /var/log/syslog

tail: Mostrar las últimas líneas de un archivo (default 10)
  -f: Seguir el archivo en tiempo real (para logs activos)
  -n: Número de líneas a mostrar
  tail archivo.log
  tail -f /var/log/apache2/access.log

clear: Limpiar toda la pantalla del terminal para mejor visualización
  clear

exit: Cerrar la sesión actual o salir del terminal
  exit

## Asignando una cuenta de usuario adicional para asegurar buen uso del VPS

adduser: Crear nuevo usuario de forma interactiva con asistente paso a paso
  adduser matichelo

useradd: Agregar usuario de forma manual con opciones específicas
  -G: Especifica grupos secundarios
  useradd matichelo sudo

deluser: Eliminar usuario del sistema
  --remove-home: Elimina también su directorio home
  deluser usuario1
  deluser test --remove-home

userdel: Eliminar usuario (comando más básico que deluser)
  -r: Elimina home y archivos del usuario
  userdel -r usuario2

usermod: Modificar propiedades de un usuario existente
  -aG: Añade usuario a grupo sin quitar de otros
  -l: Cambia el nombre de usuario
  -d: Cambia el directorio home
  usermod -aG sudo usuario1
  usermod -aG docker usuario1
  usermod -l nuevo_nombre viejo_nombre
  usermod -d /home/nueva_ruta usuario1

addgroup/groupadd: Crear un nuevo grupo en el sistema
  addgroup developers
  groupadd developers

delgroup/groupdel: Eliminar un grupo del sistema
  delgroup developers
  groupdel developers

gpasswd: Administrar miembros de grupos
  -a: Agregar usuario a grupo
  -d: Eliminar usuario de grupo
  -M: Establecer lista completa de miembros
  gpasswd -a usuario1 sudo
  gpasswd -d usuario1 sudo
  gpasswd -M usuario1,usuario2,usuario3 developers

newgrp: Cambiar el grupo activo del usuario en la sesión actual
  newgrp docker
  newgrp developers

passwd: Cambiar contraseña de usuario
  Sin parámetros cambia tu propia contraseña
  Como root puede cambiar contraseña de cualquier usuario
  passwd
  passwd usuario1

su: Cambiar a otro usuario sin cerrar sesión actual
  -: Cambia con el entorno completo del usuario
  su usuario1
  su -

sudo: Ejecutar un comando con privilegios de root/administrador
  -u: Ejecutar como otro usuario específico
  sudo apt update
  sudo systemctl restart nginx
  sudo -u usuario1 comando

visudo: Editar archivo sudoers de forma segura con validación de sintaxis
  -f: Editar archivo específico en sudoers.d
  visudo
  visudo -f /etc/sudoers.d/custom

whoami: Mostrar el nombre del usuario con el que estás logueado
  whoami

id: Mostrar UID, GID y grupos del usuario
  UID: ID único de usuario, GID: ID de grupo principal
  id
  id usuario1

groups: Listar todos los grupos a los que pertenece un usuario
  groups
  groups usuario1

getent: Obtener información de bases de datos del sistema (usuarios, grupos)
  passwd: Lista todos los usuarios
  group: Lista todos los grupos
  getent passwd
  getent group
  getent group sudo

chmod: Cambiar permisos de lectura, escritura y ejecución de archivos/directorios
  -R: Aplicar cambios recursivamente a carpetas
  +x: Agregar permiso de ejecución
  777: Todos los permisos (rwxrwxrwx)
  755: Propietario todo, grupo/otros lectura-ejecución
  644: Propietario lectura-escritura, grupo/otros solo lectura
  chmod 755 script.sh
  chmod +x programa.sh
  chmod -R 644 /home/usuario/documentos
  chmod u+rwx,g+rx,o+r archivo.txt
  chmod 777 archivo.txt
  chmod 644 archivo.txt

chown: Cambiar el propietario (usuario y/o grupo) de archivos/directorios
  -R: Aplicar cambios recursivamente
  usuario:grupo: Cambiar usuario y grupo
  :grupo: Solo cambiar grupo
  chown usuario1 archivo.txt
  chown -R usuario1:grupo1 /var/www/html
  chown :grupo1 archivo.txt

chgrp: Cambiar solo el grupo propietario de archivos/directorios
  -R: Aplicar cambios recursivamente
  chgrp developers proyecto.txt
  chgrp -R www-data /var/www/html

## Estableciendo una capa de seguridad en el servidor VPS

apt update: Actualizar la lista de paquetes disponibles desde repositorios
  apt update

apt upgrade: Actualizar todos los paquetes instalados a sus últimas versiones
  -y: Acepta automáticamente sin pedir confirmación
  apt upgrade
  apt upgrade -y

apt install: Instalar uno o más paquetes nuevos en el sistema
  -y: Instala automáticamente sin confirmación
  apt install nginx
  apt install python3 git curl
  apt install -y nodejs

apt remove: Eliminar paquete pero mantiene archivos de configuración
  apt remove apache2

apt purge: Eliminar paquete completamente incluyendo configuraciones
  apt purge mysql-server

apt autoremove: Eliminar paquetes que fueron dependencias y ya no se necesitan
  apt autoremove

apt search: Buscar paquetes por nombre o descripción
  apt search nginx
  apt search python

apt show: Mostrar información detallada de un paquete específico
  apt show nginx

apt list: Listar paquetes instalados o disponibles
  --installed: Filtra solo paquetes instalados
  grep: Buscar patrón específico
  sudo grep -r "matichain.dev/chain.pem" /etc/nginx/
  apt list
  apt list --installed | grep python

systemctl: Controlar servicios del sistema (iniciar, detener, reiniciar, habilitar)
  status: Ver estado actual de un servicio
  start: Iniciar un servicio detenido
  stop: Detener un servicio en ejecución
  restart: Reiniciar un servicio (stop + start)
  reload: Recargar configuración sin detener servicio
  enable: Habilitar inicio automático al arrancar sistema
  disable: Deshabilitar inicio automático
  list-units: Listar todos los servicios activos
  --type=service: Filtrar solo servicios
  systemctl status nginx
  systemctl start apache2
  systemctl stop mysql
  systemctl restart ssh
  systemctl enable nginx
  systemctl disable apache2
  systemctl list-units
  systemctl list-unit-files

journalctl: Ver y analizar logs del sistema y servicios (systemd)
  -u: Ver logs de un servicio específico
  -f: Seguir logs en tiempo real (follow)
  --since: Filtrar logs desde una fecha/hora
  -xe: Mostrar últimas entradas con explicaciones
  journalctl
  journalctl -u nginx
  journalctl -f
  journalctl --since "1 hour ago"
  journalctl -xe

kill: Terminar un proceso específico usando su PID (Process ID)
  -9: Fuerza el cierre inmediato (SIGKILL)
  PID: Número de identificación del proceso
  kill 1234
  kill -9 1234

killall: Terminar todos los procesos que coincidan con un nombre
  -9: Fuerza el cierre inmediato
  killall firefox
  killall -9 python3

pkill: Terminar procesos por nombre o patrón más flexible
  -u: Terminar procesos de un usuario específico
  pkill nginx
  pkill -u usuario1

reboot: Reiniciar el sistema operativo completamente
  reboot
  sudo reboot

shutdown: Apagar o reiniciar el sistema de forma programada
  -h now: Apagar ahora (halt)
  -r now: Reiniciar ahora (reboot)
  shutdown -h now
  shutdown -r now

history: Mostrar historial de comandos ejecutados en la terminal
  grep: Filtrar por palabra clave
  history
  history | grep apt

free: Mostrar uso de memoria RAM y swap del sistema
  -h: Formato legible (MB, GB) en lugar de bytes
  free
  free -h

df: Mostrar uso de disco de todas las particiones montadas
  -h: Formato legible (MB, GB, TB)
  df
  df -h

du: Mostrar espacio usado por archivos y directorios específicos
  -s: Resumen total (no detalla subdirectorios)
  -h: Formato legible (KB, MB, GB)
  du /home/usuario
  du -sh /var/log
  du -sh *

top: Monitor interactivo de procesos y recursos del sistema en tiempo real
  top

htop: Monitor de procesos mejorado con interfaz visual (requiere instalación)
  htop

ps: Mostrar procesos en ejecución en el momento actual
  aux: Todos los procesos de todos los usuarios con detalles
  grep: Filtrar por nombre de proceso
  ps
  ps aux | grep nginx

uname: Mostrar información básica del sistema operativo
  -a: Toda la información (kernel, versión, arquitectura)
  uname
  uname -a

uptime: Mostrar tiempo que lleva el sistema encendido y carga promedio
  uptime

hostname: Mostrar o cambiar el nombre del host/servidor
  -I: Mostrar dirección IP del sistema
  hostname
  hostname -I

ip addr/ifconfig: Mostrar configuración de red e interfaces de red
  show: Especificar interfaz de red específica
  ip addr
  ip addr show eth0
  ifconfig

Editar configuración SSH: Modificar comportamiento del servidor SSH (puerto, autenticación, permisos)
  Port: Cambiar puerto por defecto (22)
  PermitRootLogin: Permitir/denegar login directo como root
  PasswordAuthentication: Habilitar/deshabilitar login por contraseña
  PubkeyAuthentication: Habilitar autenticación por llave pública
  sudo nano /etc/ssh/sshd_config
  sudo vim /etc/ssh/sshd_config

Verificar configuración SSH: Listar archivos de configuración del servidor SSH
  ll /etc/ssh/
  ls -la /etc/ssh/

Reiniciar servicio SSH: Aplicar cambios después de modificar configuración
  sudo systemctl restart sshd
  sudo systemctl restart ssh

Verificar estado servicio SSH: Comprobar si SSH está activo y funcionando
  sudo systemctl status sshd
  sudo systemctl status ssh

ufw status: Mostrar estado actual del firewall y reglas activas
  verbose: Información detallada con políticas
  numbered: Muestra número de cada regla para eliminar fácilmente
  sudo ufw status
  sudo ufw status verbose
  sudo ufw status numbered

ufw enable: Activar el firewall y aplicar reglas configuradas
  sudo ufw enable

ufw disable: Desactivar el firewall temporalmente
  sudo ufw disable

ufw allow: Permitir tráfico entrante en puerto o servicio específico
  puerto/protocolo: Especifica puerto y TCP o UDP
  from: Permite desde IP o red específica
  sudo ufw allow "OpenSSH"
  sudo ufw allow 22
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  sudo ufw allow from 192.168.1.0/24

ufw deny: Bloquear tráfico entrante de puerto, servicio o IP
  sudo ufw deny 23
  sudo ufw deny from 192.168.1.100

ufw delete: Eliminar una regla del firewall existente
  Número: Elimina regla por número (ver con ufw status numbered)
  sudo ufw delete allow 80
  sudo ufw delete 1

ufw app list: Listar aplicaciones preconfiguradas disponibles
  sudo ufw app list

ufw app info: Mostrar puertos y detalles de una aplicación preconfigurada
  sudo ufw app info "OpenSSH"
  sudo ufw app info "Nginx Full"

fail2ban-client status: Ver estado de Fail2ban y servicios protegidos
  Muestra jails activas y número de IPs baneadas
  sudo fail2ban-client status
  sudo fail2ban-client status sshd
  sudo fail2ban-client status nginx

fail2ban-client unbanip: Desbanear una dirección IP específica de un servicio
  set: Especifica jail (servicio) y acción
  sudo fail2ban-client set sshd unbanip 179.6.0.169
  sudo fail2ban-client set nginx-http-auth unbanip 192.168.1.100

fail2ban-client banip: Banear manualmente una IP en un servicio específico
  sudo fail2ban-client set sshd banip 192.168.1.100

## Instalando y configurando el servidor web Nginx en el VPS

apt install nginx: Instalar servidor web Nginx desde repositorios
  sudo apt install nginx

Navegar a directorio de configuración Nginx: Acceder a carpetas de configuración de Nginx
  /etc/nginx/: Directorio principal
  sites-available/: Configuraciones disponibles
  sites-enabled/: Configuraciones activas
  cd /etc/nginx/
  cd /etc/nginx/sites-available/
  cd /etc/nginx/sites-enabled/
  cd /var/log/nginx/
  cd /var/www/html/

Editar archivo principal de configuración: Modificar settings globales de Nginx
  sudo nano /etc/nginx/nginx.conf
  nano nginx.conf

Crear nuevo sitio: Copiar plantilla default y editar para nuevo dominio
  sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/matichain.dev
  sudo nano /etc/nginx/sites-available/matichain.dev

Habilitar sitio: Crear enlace simbólico de sites-available a sites-enabled
  -s: Crear enlace simbólico (symbolic link)
  sudo ln -s /etc/nginx/sites-available/matichain.dev /etc/nginx/sites-enabled/
  sudo ln -s /etc/nginx/sites-available/api.matichain.dev /etc/nginx/sites-enabled/

Deshabilitar sitio: Eliminar enlace simbólico de sites-enabled
  sudo rm /etc/nginx/sites-enabled/default
  sudo rm /etc/nginx/sites-enabled/matichain.dev

Crear directorio para sitio: Crear carpeta para archivos web del dominio
  sudo mkdir /var/www/matichain.dev
  sudo chown -R matichelo:www-data /var/www/matichain.dev
  sudo chmod 750 /var/www/matichain.dev
    Permisos del directorio (750):
      Usuario (7=rwx): leer, escribir, ejecutar (acceso completo)
      Grupo (5=r-x): leer, ejecutar (puede listar y acceder)
      Otros (0=---): nada (sin acceso)
    Resultado: El usuario puede gestionar, Nginx (www-data) puede acceder, otros bloqueados
  sudo chmod 640 /var/www/matichain.dev/*
    Permisos de archivos (640):
      Usuario (6=rw-): leer, escribir (puede editar archivos)
      Grupo (4=r--): solo leer (Nginx puede servir archivos)
      Otros (0=---): nada (sin acceso)
    Resultado: Tú editas (index.html, imágenes), Nginx solo lee, otros bloqueados
  sudo nano /var/www/matichain.dev/index.html

Copiar estructura de sitio: Duplicar configuración de un sitio existente
  -r: Copia recursiva (todo el contenido)
  sudo cp -r matichain.dev/ api.matichain.dev/

nginx -t: Probar configuración sin aplicarla (detecta errores de sintaxis)
  sudo nginx -t

nginx -T: Mostrar configuración completa consolidada de todos los archivos
  sudo nginx -T

systemctl reload nginx: Recargar configuración sin interrumpir conexiones activas
  sudo systemctl reload nginx

systemctl restart nginx: Reiniciar servicio completamente (cierra conexiones)
  sudo systemctl restart nginx

systemctl status nginx: Verificar si Nginx está activo y funcionando correctamente
  sudo systemctl status nginx

Permitir HTTP y HTTPS en firewall: Abrir puertos 80 y 443 en UFW
  sudo ufw allow "Nginx HTTP"
  sudo ufw allow "Nginx HTTPS"
  sudo ufw allow "Nginx Full"

## Instalando y configurando MySQL

apt install mysql-server: Instalar servidor de base de datos MySQL
  sudo apt install mysql-server
  sudo apt update && sudo apt install mysql-server

mysql --version: Verificar versión de MySQL instalada
  mysql --version

mysql_secure_installation: Asistente de configuración inicial de seguridad MySQL
  Establece contraseña root, elimina usuarios anónimos, deshabilita login remoto root
  sudo mysql_secure_installation

Conectar a MySQL: Acceder a consola de MySQL para ejecutar consultas SQL
  -u: Usuario
  -p: Solicita contraseña
  database_name: Conectar directamente a una base de datos
  sudo mysql
  mysql -u root -p
  sudo mysql -u root -p
  mysql -u usuario -p database_name

Iniciar/Detener/Reiniciar MySQL: Controlar estado del servicio MySQL
  sudo systemctl start mysql
  sudo systemctl stop mysql
  sudo systemctl restart mysql
  sudo systemctl status mysql

Eliminar MySQL completamente: Desinstalar MySQL y eliminar todos sus datos
  purge: Elimina paquetes y configuraciones
  rm -rf: Elimina directorios de datos manualmente
  sudo systemctl stop mysql
  sudo apt purge mysql-server mysql-client mysql-common mysql-server-core-*
  sudo rm -rf /var/lib/mysql
  sudo rm -rf /etc/mysql
  sudo apt autoremove
  sudo apt autoclean

## Administrando usuarios, bases de datos y privilegios en MySQL

CREATE USER: Crear nuevo usuario de MySQL con contraseña
  @localhost: Usuario solo puede conectarse localmente
  @'%': Usuario puede conectarse desde cualquier host
  IDENTIFIED BY: Establece la contraseña del usuario
  CREATE USER matichain_dev@localhost IDENTIFIED BY 'password123';
  CREATE USER 'usuario'@'%' IDENTIFIED BY 'contraseña_segura';
  CREATE USER 'admin'@'192.168.1.%' IDENTIFIED BY 'pass123';

DROP USER: Eliminar un usuario de MySQL completamente
  DROP USER 'usuario'@'localhost';
  DROP USER 'matichain_dev'@'localhost';

ALTER USER: Modificar usuario existente (contraseña, plugin autenticación)
  IDENTIFIED BY: Cambiar contraseña
  IDENTIFIED WITH: Cambiar método de autenticación
  ALTER USER 'root'@'localhost' IDENTIFIED BY 'nueva_password';
  ALTER USER 'usuario'@'localhost' IDENTIFIED WITH mysql_native_password BY 'pass123';

SELECT user FROM mysql.user: Ver lista de usuarios de MySQL
  Muestra usuarios, hosts y plugins de autenticación
  SELECT user, host, plugin FROM mysql.user;
  SELECT user, host FROM mysql.user;

CREATE DATABASE: Crear nueva base de datos en MySQL
  IF NOT EXISTS: Solo crea si no existe (evita errores)
  CHARACTER SET: Define codificación de caracteres
  CREATE DATABASE hotel;
  CREATE DATABASE matichain_db;
  CREATE DATABASE tienda CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  CREATE DATABASE IF NOT EXISTS proyecto;

DROP DATABASE: Eliminar base de datos y todo su contenido permanentemente
  IF EXISTS: Solo elimina si existe (evita errores)
  DROP DATABASE hotel;
  DROP DATABASE IF EXISTS test_db;

SHOW DATABASES: Listar todas las bases de datos disponibles en el servidor
  SHOW DATABASES;
  SHOW DATABASES LIKE 'mati%';

USE: Seleccionar base de datos para trabajar con ella
  USE hotel;
  USE matichain_db;

SHOW TABLES: Mostrar todas las tablas de la base de datos actual
  SHOW TABLES;
  SHOW TABLES FROM hotel;

DESCRIBE: Mostrar estructura de una tabla (columnas, tipos, claves)
  DESCRIBE nombre_tabla;
  DESCRIBE usuarios;
  DESC clientes;

GRANT: Otorgar privilegios específicos a un usuario sobre base de datos o tablas
  ALL PRIVILEGES: Todos los permisos (SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc)
  SELECT, INSERT, UPDATE, DELETE: Permisos específicos de lectura/escritura
  ON database.*: Aplica a todas las tablas de la base de datos
  ON database.table: Aplica solo a tabla específica
  TO: Especifica el usuario que recibe los privilegios
  GRANT ALL PRIVILEGES ON hotel.* TO matichain_dev@localhost;
  GRANT ALL PRIVILEGES ON *.* TO 'admin'@'localhost';
  GRANT SELECT, INSERT, UPDATE, DELETE ON matichain_db.* TO 'matichain_dev'@'localhost';
  GRANT SELECT ON tienda.productos TO 'lector'@'localhost';
  GRANT CREATE, DROP ON proyecto.* TO 'desarrollador'@'%';

REVOKE: Revocar privilegios previamente otorgados a un usuario
  REVOKE DELETE ON hotel.* FROM 'matichain_dev'@'localhost';
  REVOKE ALL PRIVILEGES ON *.* FROM 'usuario'@'localhost';

SHOW GRANTS: Mostrar privilegios de un usuario específico
  FOR: Especifica el usuario a consultar
  SHOW GRANTS FOR 'matichain_dev'@'localhost';
  SHOW GRANTS FOR 'root'@'localhost';
  SHOW GRANTS FOR CURRENT_USER;

FLUSH PRIVILEGES: Recargar tabla de privilegios para aplicar cambios inmediatamente
  Necesario después de modificar privilegios directamente en tablas de sistema
  FLUSH PRIVILEGES;

SET PASSWORD: Cambiar contraseña de usuario MySQL
  FOR: Especifica usuario (si no se indica, cambia la del usuario actual)
  SET PASSWORD FOR 'matichain_dev'@'localhost' = 'nueva_password';
  SET PASSWORD = 'mi_nueva_password';

exit/quit: Salir de la consola de MySQL
  exit;
  quit;
  \q

## Haciendo Nginx y los sitios del VPS más seguros y eficientes

Editar snippets de seguridad: Crear archivos reutilizables con headers de seguridad HTTP
  sudo nano /etc/nginx/snippets/security-headers.conf
  sudo nano /etc/nginx/snippets/dos-protection.conf

Ver archivos de configuración: Leer contenido de archivos de configuración
  cat security-headers.conf
  cat /etc/nginx/nginx.conf

Ver logs de Nginx: Revisar registros de acceso y errores de Nginx
  access.log: Todas las peticiones HTTP
  error.log: Errores y problemas del servidor
  sudo nano /var/log/nginx/access.log
  sudo nano /var/log/nginx/error.log
  cat /var/log/nginx/access.log
  tail -f /var/log/nginx/access.log

Configurar Fail2ban para Nginx: Instalar y configurar protección contra ataques
  jail.local: Archivo de configuración personalizada (no editar jail.conf)
  sudo apt install fail2ban
  cd /etc/fail2ban/
  sudo nano /etc/fail2ban/jail.local
  sudo systemctl restart fail2ban

## Letsencrypt para establecer conexiones HTTPS en los sitios del VPS

Instalar Certbot: Instalar cliente de Let's Encrypt para certificados SSL gratis
  snapd: Sistema de paquetes necesario para Certbot
  --classic: Modo de instalación con todos los permisos
  sudo apt install snapd
  sudo snap install --classic certbot
  sudo ln -s /snap/bin/certbot /usr/bin/certbot

Ver ayuda de Certbot: Mostrar comandos y opciones disponibles
  sudo certbot --help
  sudo certbot

Obtener certificado para Nginx: Solicitar y configurar certificado SSL automáticamente
  --nginx: Plugin para Nginx (configura automáticamente)
  -d: Especifica dominio(s)
  --hsts: Habilita HTTP Strict Transport Security
  --staple-ocsp: Habilita OCSP Stapling para mejor rendimiento
  sudo certbot --nginx
  sudo certbot --nginx -d matichain.dev
  sudo certbot --nginx -d matichain.dev -d api.matichain.dev
  sudo certbot --nginx --hsts --staple-ocsp -d matichain.dev -d api.matichain.dev -d test.matichain.dev
Expandir certificado existente
  sudo certbot --nginx --expand -d matichain.dev -d api.matichain.dev -d test.matichain.dev -d wordpress.matichain.dev -d laravel.matichain.dev

Renovar certificados: Renovar certificados SSL antes de que expiren
  --dry-run: Simula renovación sin aplicar cambios (para probar)
  sudo certbot renew
  sudo certbot renew --dry-run

Ver certificados instalados: Listar todos los certificados activos y sus dominios
  sudo certbot certificates
Eliminar el antiguo (sin -0001)
  sudo certbot delete --cert-name matichain.dev


Verificar timers de renovación automática: Comprobar si renovación automática está activa
  sudo systemctl list-timers

Editar crontab para renovación: Programar renovación automática de certificados
  -e: Editar crontab
  -l: Listar tareas programadas
  sudo crontab -e
  sudo crontab -l
  crontab -l

## Preparando el VPS para usar proyectos basados en PHP

add-apt-repository: Agregar repositorios PPA (Personal Package Archive) externos
  ppa:ondrej/php: Repositorio de Ondrej con versiones más recientes de PHP
  sudo add-apt-repository ppa:ondrej/php
  sudo apt update

apt install php-fpm: Instalar PHP-FPM (FastCGI Process Manager) para Nginx
  PHP-FPM: Gestor de procesos PHP optimizado para servidores web
  Más eficiente que mod_php para Nginx
  sudo apt install php-fpm

php --version: Verificar versión de PHP instalada en el sistema
  php --version
  php -v

Navegar a directorio de configuración PHP: Acceder a archivos de configuración de PHP
  /etc/php/: Directorio principal de configuración
  8.4/: Versión de PHP instalada
  fpm/: Configuración de PHP-FPM
  cli/: Configuración de PHP para línea de comandos
  cd /etc/php/
  cd /etc/php/8.4/
  cd /etc/php/8.4/fpm/

Editar php.ini: Modificar configuración principal de PHP
  Cambiar límites de memoria, tamaño de archivos, tiempo de ejecución, etc.
  sudo nano /etc/php/8.4/fpm/php.ini
  sudo nano /etc/php/8.4/cli/php.ini

systemctl reload php-fpm: Recargar configuración de PHP-FPM sin detener servicio
  Aplica cambios en php.ini sin interrumpir sitios web activos
  sudo systemctl reload php8.4-fpm
  sudo systemctl reload php8.4-fpm.service
  sudo systemctl restart php8.4-fpm
  sudo systemctl status php8.4-fpm

apt install extensiones PHP: Instalar módulos adicionales necesarios para aplicaciones PHP
  php-mysql: Conexión a bases de datos MySQL/MariaDB
  php-sqlite3: Soporte para SQLite
  php-curl: Cliente HTTP para hacer peticiones externas
  php-gd: Procesamiento de imágenes (GD Library)
  php-mbstring: Manejo de cadenas multi-byte (caracteres UTF-8)
  php-xml: Procesamiento de XML
  php-xmlrpc: Soporte para XML-RPC
  php-zip: Compresión y descompresión de archivos ZIP
  sudo apt install php-mysql php-sqlite3 php-curl php-gd php-mbstring php-xml php-xmlrpc php-zip
  sudo apt install php8.4-mysql php8.4-curl php8.4-gd

php -r: Ejecutar código PHP directamente desde línea de comandos
  Útil para scripts de una línea o instaladores
  php -r "phpinfo();"
  php -r "echo PHP_VERSION;"

Instalar Composer: Gestor de dependencias para PHP (similar a npm para Node.js)
  Paso 1: Descargar instalador
  php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
  
  Paso 2: Verificar integridad del instalador con hash SHA384
  php -r "if (hash_file('sha384', 'composer-setup.php') === 'HASH_ACTUAL') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); exit(1); }"
  
  Paso 3: Ejecutar instalador (crea composer.phar)
  php composer-setup.php
  
  Paso 4: Eliminar instalador
  php -r "unlink('composer-setup.php');"
  
  Paso 5: Mover a directorio global para usar desde cualquier lugar
  sudo mv composer.phar /usr/local/bin/composer
  
  Paso 6: Verificar instalación
  composer --version
  composer -v

composer self-update: Actualizar Composer a la última versión disponible
  sudo composer self-update
  composer self-update

chmod +x: Dar permisos de ejecución a un archivo (hacerlo ejecutable)
  Necesario para scripts y binarios descargados
  chmod +x archivo.sh
  chmod +x wp-cli.phar

curl -O: Descargar archivo desde URL manteniendo el nombre original
  -O: Guarda con nombre del archivo remoto
  curl -O https://ejemplo.com/archivo.zip
  curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar

Instalar WP-CLI: Herramienta de línea de comandos para gestionar WordPress
  Paso 1: Descargar WP-CLI
  curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
  
  Paso 2: Verificar que funciona
  php wp-cli.phar --info
  
  Paso 3: Dar permisos de ejecución
  chmod +x wp-cli.phar
  
  Paso 4: Mover a directorio global
  sudo mv wp-cli.phar /usr/local/bin/wp
  
  Paso 5: Verificar instalación
  wp --info
  wp --version
  wp

Usar Composer: Comandos comunes para gestionar dependencias PHP
  composer init: Crear nuevo proyecto Composer
  composer install: Instalar dependencias del proyecto
  composer require: Agregar nueva dependencia
  composer update: Actualizar dependencias
  composer dump-autoload: Regenerar autoloader
  composer require vendor/package
  composer install
  composer update

Usar WP-CLI: Comandos para gestionar WordPress desde terminal
  wp core download: Descargar WordPress
  wp core install: Instalar WordPress
  wp plugin list: Listar plugins instalados
  wp plugin install: Instalar plugin
  wp plugin update: Actualizar plugins
  wp theme list: Listar temas
  wp db export: Exportar base de datos
  wp core download
  wp plugin install woocommerce --activate
  wp plugin update --all

## Desplegando un sitio WordPress en el VPS con WP-CLI

Crear configuración de sitio Nginx para WordPress: Copiar plantilla base y personalizar para WordPress
  sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/wordpress.matichain.dev
  sudo nano /etc/nginx/sites-available/wordpress.matichain.dev

Verificar versión de PHP-FPM disponible: Listar sockets de PHP-FPM para configurar Nginx
  ll /run/php/
  ls -la /run/php/

Habilitar sitio WordPress en Nginx: Crear enlace simbólico para activar configuración
  sudo ln -s /etc/nginx/sites-available/wordpress.matichain.dev /etc/nginx/sites-enabled/
  sudo ln -s /etc/nginx/sites-available/wordpress.dominio.com /etc/nginx/sites-enabled/

Listar sitios habilitados: Verificar qué sitios están activos en Nginx
  ll /etc/nginx/sites-enabled/
  ls -la /etc/nginx/sites-enabled/

Validar y recargar Nginx: Probar configuración y aplicar cambios
  sudo nginx -t
  sudo systemctl reload nginx.service
  sudo systemctl reload nginx

Expandir certificado SSL para WordPress: Agregar nuevo subdominio al certificado existente
  --expand: Agregar dominios sin crear certificado duplicado
  sudo certbot --nginx --expand -d matichain.dev -d api.matichain.dev -d wordpress.matichain.dev
  sudo certbot --nginx --expand -d dominio.com -d www.dominio.com -d wordpress.dominio.com

Ver configuración de sitio: Revisar archivo de configuración completo
  cat /etc/nginx/sites-available/wordpress.matichain.dev
  cat wordpress.matichain.dev

Crear directorio para WordPress: Crear carpeta donde se instalará WordPress
  sudo mkdir /var/www/wordpress.matichain.dev
  sudo mkdir /var/www/wordpress.dominio.com

Descargar WordPress con WP-CLI: Obtener última versión de WordPress en directorio actual
  --allow-root: Permite ejecutar WP-CLI como root (necesario con sudo)
  --locale: Especificar idioma (es_ES, es_MX, en_US)
  --version: Descargar versión específica
  sudo wp core download --allow-root
  sudo wp core download --allow-root --locale=es_ES
  sudo wp core download --allow-root --version=6.4

Cambiar propietario de archivos WordPress: Asignar permisos correctos al servidor web
  -R: Recursivo (aplica a todos los archivos y subdirectorios)
  www-data: Usuario del servidor web Nginx
  sudo chown -R www-data /var/www/wordpress.matichain.dev/
  sudo chown -R www-data:www-data /var/www/wordpress.dominio.com/
  sudo chown -R matichelo:www-data /var/www/wordpress.matichain.dev/

Cambiar grupo de archivos WordPress: Establecer grupo del servidor web
  -R: Recursivo
  sudo chgrp -R www-data /var/www/wordpress.matichain.dev/
  sudo chgrp -R www-data /var/www/wordpress.dominio.com/

Listar archivos de WordPress: Ver contenido del directorio WordPress
  ll: Listar formato largo con detalles
  -a: Mostrar archivos ocultos
  ll
  ll -a
  ls -la

Crear archivo .htaccess: Archivo de configuración para reglas de reescritura (opcional con Nginx)
  sudo nano .htaccess
  sudo touch .htaccess

Cambiar propietario de .htaccess: Permitir que servidor web modifique .htaccess
  sudo chown www-data .htaccess
  sudo chown www-data:www-data .htaccess

Ver contenido de .htaccess: Revisar reglas configuradas
  cat .htaccess
  sudo nano .htaccess

Configurar WordPress desde WP-CLI: Crear archivo wp-config.php con datos de base de datos
  --dbname: Nombre de la base de datos MySQL
  --dbuser: Usuario de MySQL
  --dbpass: Contraseña del usuario MySQL
  --dbhost: Host de MySQL (generalmente localhost)
  --locale: Idioma de WordPress
  sudo wp config create --dbname=wordpress_db --dbuser=wp_user --dbpass='password' --allow-root
  sudo wp config create --dbname=hotel --dbuser=matichain_dev --dbpass='_Pass123@_' --dbhost=localhost --locale=es_ES --allow-root

Instalar WordPress desde WP-CLI: Completar instalación con título, usuario admin y email
  --url: URL del sitio WordPress
  --title: Título del sitio
  --admin_user: Nombre de usuario administrador
  --admin_password: Contraseña del administrador
  --admin_email: Email del administrador
  sudo wp core install --url=wordpress.matichain.dev --title="Mi Blog" --admin_user=admin --admin_password='Admin123!' --admin_email=admin@matichain.dev --allow-root
  sudo wp core install --url=https://wordpress.dominio.com --title="Sitio WordPress" --admin_user=administrador --admin_password='Secure@Pass123' --admin_email=correo@dominio.com --allow-root

Verificar instalación WordPress: Comprobar que WordPress está correctamente instalado
  sudo wp core version --allow-root
  sudo wp core is-installed --allow-root

Establecer permisos recomendados WordPress: Configurar permisos seguros para archivos y directorios
  Directorios: 755 (rwxr-xr-x)
  Archivos: 644 (rw-r--r--)
  sudo find /var/www/wordpress.matichain.dev/ -type d -exec chmod 755 {} \;
  sudo find /var/www/wordpress.matichain.dev/ -type f -exec chmod 644 {} \;