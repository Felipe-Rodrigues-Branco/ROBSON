# README: Broker e Cliente MQTT Seguro

Este projeto implementa um sistema de mensagens MQTT (Message Queuing Telemetry Transport) seguro, com autenticação mútua baseada em certificados digitais e criptografia de ponta a ponta. O sistema é composto por um broker (servidor) e um cliente, ambos desenvolvidos em Python.

### Funcionalidades Principais

*   **Autenticação Mútua por Certificados:** Tanto o broker quanto os clientes utilizam certificados digitais para autenticação. O broker atua como uma Autoridade Certificadora (CA) intermediária para os clientes, emitindo e assinando seus certificados.
*   **Criptografia de Envelope (Cliente-Broker):** A comunicação entre o cliente e o broker é protegida por um esquema de envelopamento digital próprio, utilizando criptografia assimétrica (RSA) para a chave simétrica (AES) e criptografia simétrica para os dados.
*   **Criptografia Ponta-a-Ponta (Cliente-Cliente):** As mensagens publicadas pelos clientes podem ser criptografadas de ponta a ponta, garantindo que apenas o remetente e o destinatário final possam ler o conteúdo, mesmo que o broker seja comprometido. O broker apenas encaminha o payload criptografado sem acesso ao seu conteúdo.
*   **Geração de CSR:** Um script auxiliar permite a geração de Certificate Signing Requests (CSRs) para entidades que desejam obter um certificado.
*   **Interface Interativa do Cliente:** O cliente possui um shell interativo para facilitar os testes de subscrição, publicação e outras operações.

### Estrutura do Projeto
