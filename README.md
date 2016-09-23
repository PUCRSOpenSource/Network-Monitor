# Manual

Para Compilação executar o comando `gcc monitor.c`

Para executar o programa utilizar o comando `sudo ./a.out interface num-packages`

Os dois argumentos para execução do programa são:

- Interface de rede a ser monitorada.
- Número de pacotes para monitorar antes de mostrar o relatório.

# Definição do Primeiro Trabalho

O trabalho consiste em desenvolver um monitor de rede para geração de estatísticas e
alertas sobre o tráfego da rede. O monitor deve apresentar as informações sobre o tráfego
através de uma interface textual ou gráfica. O usuário deve informar a interface que deseja
monitorar ao iniciar a execução do monitor. A interface escolhida deve ser configurada
para o modo promíscuo. O monitor deve ser implementado em C ou C++, usando socket
raw, e deve implementar as seguintes funcionalidades:

- Geral
  - [x] Apresentar min/max/média do tamanho dos pacotes recebidos
- Nível de Enlace
  - [x] Quantidade e porcentagem de ARP Requests e ARP Reply
- Nível de Rede
  - [x] Quantidade e porcentagem de pacotes ICMP
  - [x] Quantidade e porcentagem de ICMP Echo Request e ICMP Echo Reply
  - [x] Lista com os 5 IPs mais acessados na rede
- Nível de Transporte
  - [x] Quantidade e porcentagem de pacotes UDP
  - [x] Quantidade e porcentagem de pacotes TCP
  - [ ] Número de conexões TCP iniciadas
  - [x] Lista com as 5 portas TCP mais acessadas
  - [x] Lista com as 5 portas UDP mais acessadas
- Nível de Aplicação
  - [x] Quantidade e porcentagem de pacotes HTTP
  - [x] Quantidade e porcentagem de pacotes DNS
  - [x] Quantidade e porcentagem para outros 2 protocolos de aplicação quaisquer
  - [ ] Lista com os 5 sites mais acessados
