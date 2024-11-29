# Script de Instalação e Configuração do Auditd com Aushape

Este script automatiza a instalação e configuração de ferramentas de monitoramento, como o auditd, aushape e rsyslog, em distribuições Linux compatíveis. Ele é especialmente útil para configurar sistemas de auditoria e envio de logs para o SIEM.

O AuditD por si só, gera muitos logs para um mesmo evento. A ideia do Aushape é agregar essas informações de mesmo evento e mostrar com um só em formato JSON. 

## Estrutura e funcionalidades deste script

- Detecta automaticamente o sistema operacional e verifica compatibilidade.
- Instala dependências necessárias para o funcionamento do auditd e aushape.
- Configura o auditd com regras de auditoria(1).
- Instala e configura o Aushape(2) como um plugin do auditd.
- Configura o rsyslog para envio de logs para um coletor central.
- Adiciona uma tarefa no cron para enviar logs de "heartbeat" periodicamente (opcional).
- Gera um log detalhado do processo de instalação em /var/log/install_script.log.

# Testes de Compatibilidade em vários SOs

Abaixo documento os resultados dos testes realizados em diferentes versões do Linux para verificar a compatibilidade e funcionalidade do script.

Os testes foram feitos em VMs prontas da OSBoxes.

Todas as VMs ao iniciá-las foram feitas o `apt update` e logo após inicado o script.

Teste em ambiente de homologação. <span style="color: red; font-weight: bold;">Em ambiente de produção use por sua conta e risco.</span>

## Tabela de Testes

| Distribuição          | Versão         | Arquitetura  | Compatível (Sim/Não) | Funcionou (Sim/Não) | Observações|
|:---------------------:|:--------------:|:------------:|:--------------------:|:-------------------:|:-----------|
| Ubuntu Server              | 24.04          | 64bit       | Sim                  | Sim                 |
| Ubuntu Server              | 23.10          | 64bit       | Sim                  | Não                 | Problemas em atualizar repositórios. Precisa configurar lista de repos e testar novamente.|
| Ubuntu Server              | 22.04          | 64bit       | Sim                  | Parcialmente        |Falha ao converter logs para json. Precisa revisar as configurações para identificar o problema.|
| Ubuntu Server              | 20.04.4          | 64bit       | Sim                  | Sim                 ||
| Ubuntu Server              | 18.04.6          | 64bit       | Sim                  | Sim                 ||
| Debian               | 10 CLI  | 32bit       | Sim                   | Não                  | Audit: backlog limit exceeded. Backlog limit em 8192. Aumentar limite e verificar se o problema resolve. Por ser 23bits não vou lançar muitos esforços na correção.|
| Debian               | 11 Server  | 32bit       | Sim                   | Não                  |O script não conseguiu reiniciar o audit. Deu algum problema ao reiniciar o serviço e travou no kernel(?). Quebrou a VM... Como é 32bits, nem vou tentar corrigir. |
| Debian               | 11 Server  | 64bit       | Sim                   | Sim                  ||

## Observações

- **Compatível**: Indica se o script pode ser executado na distribuição/versão sem erros de dependência.
- **Funcionou**: Indica se o script funcionou como esperado após execução ou tiveram erros no ambiente.
- **Erros comuns encontrados:** Muitos problemas encontrados em ambiente 32bits. Muitos deles relacionados ao próprio auditd. Não foi realizado nenhum tipo de troubleshoot para avaliação.

### Como Reproduzir os Testes

1. Baixe o script para o ambiente de teste:
   ```bash
   wget https://github.com/seuusuario/seurepositorio.git
   chmod +x LogCollector.sh
   sudo ./LogCollector.sh
   ```

### Referências

1. https://github.com/Neo23x0/auditd/blob/master/audit.rules
2. https://github.com/Scribery/aushape