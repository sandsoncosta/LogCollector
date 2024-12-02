#!/bin/bash

# Nome do Script: LogCollector.sh
# Autor: Sandson Costa
# Data: 28/11/2024
# LinkedIn: https://www.linkedin.com/in/sandsoncosta
# Licença: MIT

# Configuração do log
exec > >(tee -a /var/log/install_script.log) 2>&1

# Definição de cores
RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # Sem cor

# Verifica se o script está sendo executado como root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Por favor, execute este script como root.${NC}"
  exit 1
fi

# Solicita o IP do servidor coletor/syslog
echo -e "${YELLOW}[*] Digite o IP do servidor do coletor/syslog:${NC}"
read ip_collector

# Detecta a versão do SO
echo -e "${YELLOW}[*] Detectando versão do sistema operacional...${NC}"
os_name=$(lsb_release -is 2>/dev/null || grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')

case "$os_name" in
  ubuntu|debian|centos|rhel|fedora|opensuse)
    echo -e "${GREEN}[+] Sistema detectado:${NC} $os_name"
    ;;
  *)
    echo -e "${RED}[!] Sistema não compatível com este script.${NC}"
    exit 1
    ;;
esac

# Teste de conexão com a Internet
echo -e "${YELLOW}[*] Verificando conexão com a Internet...${NC}"
if ping -c 1 google.com &>/dev/null || ping -c 1 8.8.8.8 &>/dev/null; then
  echo -e "${GREEN}[+] Conexão detectada.${NC}"
elif
  echo -e "${RED}[!] Sem conexão com a internet.${NC}"
  exit 1
fi

# Instalação de pacotes necessários
echo -e "${YELLOW}[*] Instalando pacotes necessários...${NC}"

if [[ "$os_name" =~ (ubuntu|debian) ]]; then
  apt-get install -y git curl wget auditd gcc make autoconf automake libtool pkg-config
elif [[ "$os_name" =~ (centos|rhel|fedora) ]]; then
  yum install -y git curl wget audit gcc make autoconf automake libtool pkg-config
elif [[ "$os_name" == "opensuse" ]]; then
  zypper install -y git curl wget audit gcc make autoconf automake libtool pkg-config
fi

# Baixa e configura regras do auditd
echo -e "${YELLOW}[*] Baixando e configurando regras do auditd...${NC}"

if command -v wget &>/dev/null; then
  wget -O /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
elif command -v curl &>/dev/null; then
  curl -o /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules
fi

# Cria um diretório temporário para o download do Aushape
temp_dir=$(mktemp -d)
cd "$temp_dir"

# Instalação do Aushape
echo -e "${YELLOW}[*] Preparando instalação do Aushape...${NC}"

if command -v git &>/dev/null; then
  git clone https://github.com/Scribery/aushape.git
  cd aushape
else
  echo -e "${YELLOW}[!] git não encontrado. Usando curl para baixar o Aushape...${NC}"
  
  curl -L https://github.com/Scribery/aushape/archive/refs/heads/master.tar.gz -o aushape.tar.gz
  tar -xvzf aushape.tar.gz
  cd aushape-master
fi

echo -e "${YELLOW}[*] Configurando e instalando o Aushape...${NC}"
autoreconf -i -f
./configure --prefix=/usr --sysconfdir=/etc && make
echo -e "${YELLOW}[+] Instalando pacote... aushape${NC}"
make install

# Cria o arquivo aushape-audispd-plugin
echo -e "${YELLOW}[+] Configurando regras de logs.${NC}"
cat <<EOF > /usr/bin/aushape-audispd-plugin
#!/bin/sh
exec /usr/bin/aushape -l json --events-per-doc=none --fold=all -o syslog
EOF
chmod +x /usr/bin/aushape-audispd-plugin

# Verifica qual diretório existe e cria o arquivo de configuração
if [ -d "/etc/audisp" ]; then
  config_dir="/etc/audisp/plugins.d"
elif [ -d "/etc/audit" ]; then
  config_dir="/etc/audit/plugins.d"
else
  echo -e "${RED}[!] Nenhum diretório /etc/audisp ou /etc/audit encontrado. Não foi possível criar o arquivo de configuração.${NC}"
  echo -e "${RED}[!] Por favor entre em contato com o suporte para configuração manual.${NC}"
  exit 1
fi

# Cria o arquivo de configuração do Aushape no diretório correto
echo -e "${YELLOW}[+] Criando .conf do aushape...${NC}"
cat <<EOF > $config_dir/aushape.conf
active = yes
direction = out
path = /usr/bin/aushape-audispd-plugin
type = always
format = string
EOF

echo -e "${YELLOW}[+] Arquivo de configuração criado em: $config_dir/aushape.conf${NC}"

# Reinicie o serviço auditd
echo -e "${YELLOW}[+] Reinciando auditd...${NC}"
if systemctl list-unit-files | grep -q "auditd.service"; then
  systemctl restart auditd
else
  echo -e "${RED}[!] Serviço auditd não encontrado.${NC}"
fi

# Configuração do rsyslog
echo -e "${YELLOW}[*] Configurando o rsyslog...${NC}"
if ! command -v rsyslogd &>/dev/null; then
  echo -e "${YELLOW}[!] rsyslog não encontrado. Instalando...${NC}"
  if [[ "$os_name" =~ (ubuntu|debian) ]]; then
    apt-get install -y rsyslog
  elif [[ "$os_name" =~ (centos|rhel|fedora) ]]; then
    yum install -y rsyslog
  elif [[ "$os_name" == "opensuse" ]]; then
    zypper install -y rsyslog
  fi
else
  echo -e "${YELLOW}[+] rsyslog já está instalado.${NC}"
fi

# Agora, faz o backup do arquivo rsyslog.conf
if [ -f "/etc/rsyslog.conf" ]; then
  backup_path="/etc/rsyslog.conf.backup.$(date +%F_%T)"
  echo -e "${YELLOW}[*] Backup do arquivo rsyslog.conf criado em ${backup_path}${NC}"
  cp /etc/rsyslog.conf "$backup_path"
fi

echo -e "${YELLOW}[+] Recriando rsyslog.conf...${NC}"
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
# sed -i "s|@@{ip_collector}|@@$ip_collector|g" /etc/rsyslog.conf

# Reinicie o auditd e rsyslog
if systemctl list-unit-files | grep -q "auditd.service"; then
  systemctl restart auditd
else
  echo -e "${RED}[!] Serviço auditd não encontrado.${NC}"
fi

if systemctl list-unit-files | grep -q "rsyslog.service"; then
  systemctl restart rsyslog
else
  echo -e "${RED}[!] Serviço rsyslog não encontrado.${NC}"
fi


# Adicione comando à cron
echo -e "${YELLOW}[+] Incluindo na cron o log de Heartbeat...${NC}"
#echo -e "*/5 * * * * root logger -p local1.info -t heartbeat 'Heartbeat log active'" >> /etc/crontab
if ! grep -q "logger -p local1.info -t heartbeat 'Heartbeat log active'" /etc/crontab; then
  echo "*/5 * * * * root logger -p local1.info -t heartbeat 'Heartbeat log active'" >> /etc/crontab
fi


# Salve o log em um arquivo .log
echo -e "${YELLOW}Log criado em /var/log/install_script.log${NC}"
echo -e "${GREEN}Script concluído!${NC}"