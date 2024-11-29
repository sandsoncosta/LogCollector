#!/bin/bash

# Nome do Script: LogCollector.sh
# Autor: Sandson Costa
# Data: 28/11/2024
# LinkedIn: https://www.linkedin.com/in/sandsoncosta
# Licença: MIT

# Copyright (c) 2024 sandsoncosta

exec > >(tee -a /var/log/install_script.log) 2>&1
# Define a cor vermelha (código ANSI)
RED='\033[0;31m'
# Reseta a cor (código ANSI)
NRED='\033[0m' # No Color
# Define a cor amarela (código ANSI)
YELLOW='\033[1;33m'
# Reseta a cor (código ANSI)
NYEL='\033[0m' # No Color
# Define a cor verde (código ANSI)
GREEN='\033[1;32m'
# Reseta a cor (código ANSI)
NGRE='\033[0m' # No Color

# Verifica se o script está sendo executado como root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Por favor, execute este script como root.${NRED}"
  exit 1
fi

# Solicita o IP do servidor do coletor/syslog
echo -e "${YELLOW}[*] Digite o IP do servidor do coletor/syslog:${NYEL}"
read ip_collector

# Detecta a versão do SO
echo -e "${YELLOW}[*] Detectando versão do SO...${NYEL}"

os_name=$(lsb_release -is 2>/dev/null || cat /etc/os-release | grep '^ID=' | cut -d '=' -f2 | tr -d '"')

# Verifica se o SO é compatível com o script
case "$os_name" in
  "Ubuntu" | "Debian" | "CentOS" | "Red Hat Enterprise Linux" | "RHEL")
    echo -e "${YELLOW}[+] Detectado:${NYEL} $os_name"
    ;;
  *)
    echo -e "${RED}[!] Sistema não compatível com o instalador... Por favor, contate o suporte para instalação manual.${NRED}"
    exit 1
    ;;
esac

# Detecta a conexão com a internet
echo -e "${YELLOW}[*] Testando conexão com a internet...${NYEL}"
if ping -c 1 8.8.8.8 &>/dev/null || ping -c 1 google.com &>/dev/null; then
  echo -e "[+] Conexão com a Internet detectada."
else
  echo -e "${RED}[!] Sem conexão com a internet... Por favor, entre em contato com o suporte para instalação manual.${NRED}"
  exit 1
fi

# Instala os pacotes necessários diretamente, sem verificação
echo -e "${YELLOW}[*] Instalando pacotes necessários...${NYEL}"

if [[ "$os_name" == "Ubuntu" || "$os_name" == "Debian" ]]; then
  required_packages="git wget curl auditd gcc make libaudit-dev libauparse-dev autoconf automake libtool pkg-config"
  apt-get install -y $required_packages
elif [[ "$os_name" == "CentOS" || "$os_name" == "RHEL" ]]; then
  required_packages="git wget curl audit gcc make audit-libs-devel autoconf automake libtool"
  yum -y install $required_packages
elif [[ "$os_name" == "Fedora" ]]; then
  required_packages="git wget curl audit gcc make audit-libs-devel autoconf automake libtool"
  dnf install -y $required_packages
elif [[ "$os_name" == "FreeBSD" ]]; then
  required_packages="git wget curl auditd gcc make autoconf automake libtool pkgconf"
  pkg install -y $required_packages
elif [[ "$os_name" == "openSUSE" ]]; then
  required_packages="git wget curl audit audit-libs gcc make autoconf automake libtool pkg-config"
  zypper install -y $required_packages
elif [[ "$os_name" == "TrueNAS" ]]; then
  required_packages="git wget curl auditd gcc make autoconf automake libtool pkgconf"
  pkg install -y $required_packages
fi


# Baixa e configura as regras do auditd
echo -e "${YELLOW}[+] Baixando e configurando regras...${NYEL}"

if [ -n "$(command -v wget)" ]; then
  wget -O /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
elif [ -n "$(command -v curl)" ]; then
  curl -o /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
fi

# Clona e configura o repositório aushape
echo -e "${YELLOW}[+] Clonando repositório Aushape...${NYEL}"
git clone https://github.com/Scribery/aushape.git
echo -e "${YELLOW}[+] Configurando instalação do Aushape...${NYEL}"
cd aushape
autoreconf -i -f
./configure --prefix=/usr --sysconfdir=/etc && make
echo -e "${YELLOW}[+] Instalando pacote... aushape${NYEL}"
make install


# Cria o arquivo aushape-audispd-plugin
echo -e "${YELLOW}[+] Configurando regras de logs.${NYEL}"
echo '#!/bin/sh' > /usr/bin/aushape-audispd-plugin
echo 'exec /usr/bin/aushape -l json --events-per-doc=none --fold=all -o syslog' >> /usr/bin/aushape-audispd-plugin
echo -e "${YELLOW}[+] Executando permissões de escrita...${NYEL}"
chmod +x /usr/bin/aushape-audispd-plugin

# Cria o arquivo aushape.conf em /etc/audisp/plugins.d/

# Verifica qual diretório existe e cria o arquivo de configuração
if [ -d "/etc/audisp" ]; then
  config_dir="/etc/audisp/plugins.d"
elif [ -d "/etc/audit" ]; then
  config_dir="/etc/audit/plugins.d"
else
  echo -e "${RED}[!] Nenhum diretório /etc/audisp ou /etc/audit encontrado. Não foi possível criar o arquivo de configuração.${NRED}"
  exit 1
fi

# Cria o arquivo de configuração do Aushape no diretório correto
echo -e "${YELLOW}[+] Criando .conf do aushape...${NYEL}"
cat <<EOF > $config_dir/aushape.conf
active = yes
direction = out
path = /usr/bin/aushape-audispd-plugin
type = always
format = string
EOF

echo -e "${YELLOW}[+] Arquivo de configuração criado em: $config_dir/aushape.conf${NYEL}"

# Reinicie o serviço auditd
echo -e "${YELLOW}[+] Reinciando auditd...${NYEL}"
systemctl restart auditd

# Crie o arquivo rsyslog.conf
echo -e "${YELLOW}[*] Verificando se o rsyslog está instalado...${NYEL}"
if ! which rsyslogd &>/dev/null; then
  echo -e "${YELLOW}[+] rsyslog não encontrado. Instalando...${NYEL}"
  
  if [[ "$os_name" == "Ubuntu" || "$os_name" == "Debian" ]]; then
    apt-get install -y rsyslog
  elif [[ "$os_name" == "CentOS" || "$os_name" == "RHEL" ]]; then
    yum -y install rsyslog
  fi
else
  echo -e "${YELLOW}[+] rsyslog já está instalado.${NYEL}"
fi

# Agora, faz o backup do arquivo rsyslog.conf
if [ -f "/etc/rsyslog.conf" ]; then
  echo -e "${YELLOW}[*] Backup do arquivo rsyslog.conf criado em /etc/rsyslog.conf.backup${NYEL}"
  mv /etc/rsyslog.conf /etc/rsyslog.conf.backup
else
  echo -e "${YELLOW}[!] Arquivo rsyslog.conf não encontrado, criando novo arquivo de configuração.${NYEL}"
fi

echo -e "${YELLOW}[+] Recriando rsyslog.conf...${NYEL}"
cat <<EOF > /etc/rsyslog.conf
#################
#### MODULES ####
#################

module(load="imuxsock") # provides support for local system logging
# module(load="imklog")   # provides kernel logging support


###########################
#### GLOBAL DIRECTIVES ####
###########################

\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

\$FileOwner root
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022

\$WorkDirectory /var/spool/rsyslog

\$IncludeConfig /etc/rsyslog.d/*.conf

###############
#### RULES ####
###############

auth,authpriv.*                 /var/log/auth.log
# *.*;auth,authpriv.none                -/var/log/syslog
# auth,authpriv.none          -/var/log/syslog
# cron.*                                /var/log/cron.log
# daemon.*                      -/var/log/daemon.log
# kern.*                                -/var/log/kern.log
# lpr.*                         -/var/log/lpr.log
# mail.*                                -/var/log/mail.log
user.*                          -/var/log/user.log
local1.info

#
# Logging for the mail system.  Split it up so that
# it is easy to write scripts to parse these files.
#
# mail.info                     -/var/log/mail.info
# mail.warn                     -/var/log/mail.warn
# mail.err                      /var/log/mail.err

#
# Some "catch-all" log files.
#
*.=debug;       auth,authpriv.none;     news.none;mail.none     -/var/log/debug
*.=info;*.=notice;*.=warn;      auth,authpriv.none;     cron,daemon.none;       mail,news.none          -/var/log/messages

if (\$programname == "aushape") and (\$msg contains "apparmor" or \$msg contains '/usr/sbin/rsyslogd') then {
    stop
}

#
# Emergencies are sent to everybody logged in.
#
#*.emerg                                :omusrmsg:
#*.*                    @@192.168.145.35:514
auth,authpriv.*     	 	@@${ip_collector}:514
local1.info		@@${ip_collector}:514
EOF
sed -i "s|@@{ip_collector}|@@$IP_COLLECTOR|g" /etc/rsyslog.conf
# Reinicie o auditd e rsyslog
echo -e "${YELLOW}[+] Reiniciando o auditd...${NYEL}"
systemctl restart auditd
echo -e "${YELLOW}[+] Reiniciando o rsyslog...${NYEL}"
systemctl restart rsyslog

# Adicione comando à cron
echo -e "${YELLOW}[+] Incluindo na cron o log de Heartbeat...${NYEL}"
#echo -e "*/5 * * * * root logger -p local1.info -t heartbeat 'Heartbeat log active'" >> /etc/crontab
if ! grep -q "logger -p local1.info -t heartbeat 'Heartbeat log active'" /etc/crontab; then
  echo "*/5 * * * * root logger -p local1.info -t heartbeat 'Heartbeat log active'" >> /etc/crontab
fi


# Salve o log em um arquivo .log
echo -e "${YELLOW}Log criado em /var/log/install_script.log${NYEL}"
echo -e "${GREEN}Script concluído!${NGRE}"
