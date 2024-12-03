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

# Detecta a versão do SO
echo -e "${YELLOW}[*] Detectando versão do sistema operacional...${NC}"

if [ -f /etc/os-release ]; then
  os_name=$(lsb_release -is 2>/dev/null || grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
elif [ -f /etc/centos-release ]; then
  os_name=$(cat /etc/centos-release)
else
  os_name="Sistema não compatível com este script."
fi
os_name=$(echo "$os_name" | tr '[:upper:]' '[:lower:]')

# Lógica para identificar o sistema operacional
if [[ "$os_name" == *"centos"* ]]; then
  echo -e "${GREEN}[+] Sistema detectado: CentOS${NC}"
  os_name="centos"
elif [[ "$os_name" == "rhel" ]]; then
  echo -e "${GREEN}[+] Sistema detectado: Red Hat Enterprise Linux${NC}"
elif [[ "$os_name" == "ubuntu" || "$os_name" == "debian" ]]; then
  echo -e "${GREEN}[+] Sistema detectado: $os_name${NC}"
else
  echo -e "${RED}[!] Sistema não compatível com este script.${NC}"
  exit 1
fi

# Solicita o IP do servidor coletor/syslog
echo -e "${YELLOW}[*] Digite o IP do servidor do coletor/syslog:${NC}"
read ip_collector
echo -e "${YELLOW}[*] IP do servidor coletor configurado como: ${ip_collector}${NC}"

# Teste de conexão com a Internet
echo -e "${YELLOW}[*] Verificando conexão com a Internet...${NC}"
if ping -c 1 google.com &>/dev/null || ping -c 1 8.8.8.8 &>/dev/null; then
  echo -e "${GREEN}[+] Conexão detectada.${NC}"
else
  echo -e "${RED}[!] Sem conexão com a internet.${NC}"
  exit 1
fi

# Instalação de pacotes necessários
echo -e "${YELLOW}[*] Instalando pacotes necessários...${NC}"

if [[ "$os_name" =~ (ubuntu|debian|Ubuntu|Debian) ]]; then
  apt-get install -y git curl wget auditd gcc make autoconf automake libtool pkg-config rsyslog libaudit libauparse
elif [[ "$os_name" =~ (*CentOS*|*centos*|rhel|fedora) ]]; then
  yum install -y git curl wget audit gcc make autoconf automake libtool pkg-config rsyslog audit-devel audit-libs-devel
elif [[ "$os_name" == "opensuse" ]]; then
  zypper install -y git curl wget audit gcc make autoconf automake libtool pkg-config rsyslog
fi

echo -e "${GREEN}[+] Pacotes instalados com sucesso.${NC}" | tee -a /var/log/install_script.log

# Verificar se o git foi instalado corretamente
if ! command -v git &>/dev/null; then
  echo -e "${RED}[!] Git não encontrado ou não instalado corretamente.${NC} Continuando com o curl..."
fi

# Baixa e configura regras do auditd
echo -e "${YELLOW}[*] Baixando e configurando regras do auditd...${NC}"

if command -v wget &>/dev/null; then
  wget -O /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules && \
  echo -e "${GREEN}[+] Regras do auditd baixadas e configuradas.${NC}"
elif command -v curl &>/dev/null; then
  curl -o /etc/audit/rules.d/audit.rules https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules && \
  echo -e "${GREEN}[+] Regras do auditd baixadas e configuradas.${NC}"
else
  echo -e "${RED}[!] Nenhum gerenciador de downloads encontrado (wget ou curl).${NC}"
  exit 1
fi

# Cria um diretório temporário para o download do Aushape
temp_dir=$(mktemp -d)
trap "rm -rf $temp_dir" EXIT
cd "$temp_dir"

# Instalação do Aushape
echo -e "${YELLOW}[*] Preparando instalação do Aushape...${NC}"

if command -v git &>/dev/null; then
  # git clone https://github.com/Scribery/aushape.git && \
  cd aushape
else
  echo -e "${YELLOW}[!] git não encontrado. Usando curl para baixar o Aushape...${NC}"
  curl -L https://github.com/Scribery/aushape/archive/refs/heads/master.tar.gz -o aushape.tar.gz && \
  tar -xvzf aushape.tar.gz && \
  cd aushape-master
fi

echo -e "${YELLOW}[*] Configurando e instalando o Aushape...${NC}"
autoreconf -i -f && \
./configure --prefix=/usr --sysconfdir=/etc && \
make && \
echo -e "${GREEN}[+] Compilação do Aushape concluída.${NC}" && \
make install && \
echo -e "${GREEN}[+] Aushape instalado com sucesso.${NC}"

# Cria o arquivo aushape-audispd-plugin
echo -e "${YELLOW}[+] Configurando regras de logs.${NC}"
cat <<EOF > /usr/bin/aushape-audispd-plugin
#!/bin/sh
exec /usr/bin/aushape -l json --events-per-doc=none --fold=all -o syslog
EOF
chmod +x /usr/bin/aushape-audispd-plugin
echo -e "${GREEN}[+] Arquivo aushape-audispd-plugin criado e executável.${NC}"

# Verifica qual diretório existe e cria o arquivo de configuração
if [ -d "/etc/audisp/plugins.d" ]; then
  config_dir="/etc/audisp/plugins.d"
elif [ -d "/etc/audit/plugins.d" ]; then
  config_dir="/etc/audit/plugins.d"
else
  echo -e "${RED}[!] Nenhum diretório /etc/audisp/plugins.d ou /etc/audit/plugins.d encontrado. Não foi possível criar o arquivo de configuração.${NC}"
  echo -e "${RED}[!] Por favor, entre em contato com o suporte para configuração manual.${NC}"
  exit 1
fi

# Cria o arquivo de configuração do Aushape no diretório correto
echo -e "${YELLOW}[+] Criando aushape.conf...${NC}"
cat <<EOF > "$config_dir/aushape.conf"
active = yes
direction = out
path = /usr/bin/aushape-audispd-plugin
type = always
format = string
EOF
echo -e "${GREEN}[+] Arquivo de configuração criado em: $config_dir/aushape.conf${NC}"

# Reinicie o serviço auditd
echo -e "${YELLOW}[+] Reiniciando auditd...${NC}"
if systemctl restart auditd; then
  echo -e "${GREEN}[+] auditd reiniciado com sucesso.${NC}"
else
  echo -e "${RED}[!] Falha ao reiniciar auditd. Verifique o log ou reinicie manualmente.${NC}"
fi

# Configuração do rsyslog
echo -e "${YELLOW}[*] Configurando o rsyslog...${NC}"
if ! command -v rsyslogd &>/dev/null; then
  echo -e "${YELLOW}[!] rsyslogd não encontrado. Instalando...${NC}"
  if [[ "$os_name" =~ (ubuntu|debian) ]]; then
    apt-get install -y rsyslog && echo -e "${GREEN}[+] rsyslog instalado com sucesso.${NC}"
  elif [[ "$os_name" =~ (*CentOS*|*centos*|rhel|fedora) ]]; then
    yum install -y rsyslog && echo -e "${GREEN}[+] rsyslog instalado com sucesso.${NC}"
  elif [[ "$os_name" == "opensuse" ]]; then
    zypper install -y rsyslog && echo -e "${GREEN}[+] rsyslog instalado com sucesso.${NC}"
  fi
else
  echo -e "${GREEN}[+] rsyslog já está instalado.${NC}"
fi

# Backup do arquivo rsyslog.conf
if [ -f "/etc/rsyslog.conf" ]; then
  backup_path="/etc/rsyslog.conf.backup.$(date +%F_%T)"
  echo -e "${YELLOW}[*] Criando backup do rsyslog.conf em ${backup_path}${NC}"
  cp /etc/rsyslog.conf "$backup_path"
else
  echo -e "${YELLOW}[!] Arquivo rsyslog.conf não encontrado, criando novo arquivo de configuração.${NC}"
fi

# Recriando rsyslog.conf
echo -e "${YELLOW}[+] Recriando rsyslog.conf...${NC}"
cat <<EOF > /etc/rsyslog.conf
#################
#### MODULES ####
#################

module(load="imuxsock") # fornece suporte para logs do sistema local
# module(load="imklog")   # fornece suporte para logs do kernel

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
# Logging para o sistema de e-mail. Dividido para facilitar scripts de análise.
#
# mail.info                     -/var/log/mail.info
# mail.warn                     -/var/log/mail.warn
# mail.err                      /var/log/mail.err

#
# Alguns arquivos de log "catch-all".
#
*.=debug;       auth,authpriv.none;     news.none;mail.none     -/var/log/debug
*.=info;*.=notice;*.=warn;      auth,authpriv.none;     cron,daemon.none;       mail,news.none          -/var/log/messages

if (\$programname == "aushape") and (\$msg contains "apparmor" or \$msg contains '/usr/sbin/rsyslogd') then {
    stop
}

#
# Emergências são enviadas para todos os usuários logados.
#
#*.emerg                                :omusrmsg:
#*.*                    @@192.168.145.35:514
auth,authpriv.*                @@${ip_collector}:514
local1.info                    @@${ip_collector}:514
EOF

# Para o Ansible
# sed -i "s|@@{ip_collector}|@@$ip_collector|g" /etc/rsyslog.conf

# Reinicie o serviço rsyslog
echo -e "${YELLOW}[+] Reiniciando rsyslog...${NC}"
if systemctl restart rsyslog; then
  echo -e "${GREEN}[+] rsyslog reiniciado com sucesso.${NC}"
else
  echo -e "${RED}[!] Falha ao reiniciar rsyslog. Verifique o log ou reinicie manualmente.${NC}"
fi

# Adiciona comando à cron para Heartbeat
echo -e "${YELLOW}[+] Incluindo na cron o log de Heartbeat...${NC}"
echo "* * * * * root logger -p local1.info -t heartbeat 'Heartbeat log active'" >> /etc/crontab
echo "* * * * * root logger -p local1.info -t heartbeat 'Versao SO:Ubuntu Server 22.04 64bit'" >> /etc/crontab
echo -e "${GREEN}[+] Heartbeat adicionado à crontab.${NC}"

# Salva o log em um arquivo .log
echo -e "${YELLOW}Log criado em /var/log/install_script.log${NC}"
echo -e "${GREEN}Script concluído!${NC}"
