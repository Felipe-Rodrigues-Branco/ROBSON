README: Broker e Cliente MQTT Seguro
Este projeto implementa um sistema de mensagens MQTT (Message Queuing Telemetry Transport) seguro, com autenticação mútua baseada em certificados digitais e criptografia de ponta a ponta. O sistema é composto por um broker (servidor) e um cliente, ambos desenvolvidos em Python.

Funcionalidades Principais
Autenticação Mútua por Certificados: Tanto o broker quanto os clientes utilizam certificados digitais para autenticação. O broker atua como uma Autoridade Certificadora (CA) intermediária para os clientes, emitindo e assinando seus certificados.
Criptografia de Envelope (Cliente-Broker): A comunicação entre o cliente e o broker é protegida por um esquema de envelopamento digital próprio, utilizando criptografia assimétrica (RSA) para a chave simétrica (AES) e criptografia simétrica para os dados.
Criptografia Ponta-a-Ponta (Cliente-Cliente): As mensagens publicadas pelos clientes podem ser criptografadas de ponta a ponta, garantindo que apenas o remetente e o destinatário final possam ler o conteúdo, mesmo que o broker seja comprometido. O broker apenas encaminha o payload criptografado sem acesso ao seu conteúdo.
Geração de CSR: Um script auxiliar permite a geração de Certificate Signing Requests (CSRs) para entidades que desejam obter um certificado.
Interface Interativa do Cliente: O cliente possui um shell interativo para facilitar os testes de subscrição, publicação e outras operações.
Estrutura do Projeto

Run
Copy code
robson/
├── .idea/                     # Arquivos de configuração do IDE (PyCharm)
├── certificates/              # Armazena certificados (CA, broker, clientes)
│   ├── BrokerCertificado.crt
│   ├── brokerPriv.key
│   ├── ca.crt
│   ├── client1.crt
│   ├── client1.key
│   ├── client2.crt
│   ├── client2.key
│   └── ...
├── csr/                       # Armazena CSRs e chaves privadas temporárias
│   ├── broker_private_key.pem
│   └── broker_request.csr
├── generate_csr.py            # Script para gerar CSRs
├── secure_broker.py           # Implementação do broker MQTT seguro
└── secure_client.py           # Implementação do cliente MQTT seguro
Pré-requisitos
Python 3.x
Biblioteca cryptography:
bash

Run
Copy code
pip install cryptography
Como Usar
1. Geração de Certificados Iniciais (CA e Broker)
Antes de iniciar o broker, é necessário gerar os certificados da Autoridade Certificadora (CA) e do próprio broker. O projeto assume que você já possui um script generate_ca_and_broker_certs.py (não fornecido no contexto, mas essencial para o funcionamento).

Passos esperados:

Execute o script generate_ca_and_broker_certs.py (ou equivalente) para criar:
certificates/ca.crt: Certificado da CA raiz.
certificates/BrokerCertificado.crt: Certificado do broker, assinado pela CA.
certificates/brokerPriv.key: Chave privada do broker.
2. Iniciar o Broker
Abra um terminal e execute o script do broker:

bash

Run
Copy code
python secure_broker.py
O broker será iniciado e aguardará conexões na porta 8883 (padrão). Ele informará se os certificados necessários foram carregados com sucesso.

3. Iniciar Clientes
Abra um novo terminal para cada cliente que deseja simular. O cliente requer um client_id como argumento.

Primeira Conexão (Registro):

Se um cliente se conectar pela primeira vez (ou se seus certificados locais forem removidos), ele iniciará um processo de registro com o broker. O broker gerará um certificado para o cliente (assinado pela chave do broker) e o enviará de volta. O cliente salvará este certificado e sua chave privada localmente.

Exemplo:

bash

Run
Copy code
python secure_client.py client1
Ao executar pela primeira vez, você verá uma mensagem indicando que os certificados não foram encontrados e que o processo de registro será iniciado. Após o registro, o cliente informará que os certificados foram salvos e que é necessário reconectar.

Reconexão (Autenticação):

Após o registro inicial, o cliente já possui seus certificados. Para se autenticar e usar o broker, basta executar o comando connect no shell interativo do cliente.

Exemplo:

bash

Run
Copy code
python secure_client.py client1
No shell interativo do cliente, digite:


Run
Copy code
client1> connect
O cliente tentará se autenticar com o broker usando seus certificados. Se a autenticação for bem-sucedida, você poderá usar os comandos MQTT.

4. Comandos do Cliente (Shell Interativo)
Uma vez conectado e autenticado, o cliente oferece os seguintes comandos:

connect: Conecta (ou tenta reconectar/autenticar) ao broker.
subscribe <tópico>: Inscreve-se em um tópico.
Ex: subscribe sensores/temperatura
unsubscribe <tópico>: Remove a subscrição de um tópico.
Ex: unsubscribe sensores/temperatura
publish <tópico> <mensagem>: Publica uma mensagem em um tópico. A mensagem será envelopada digitalmente para o broker.
Ex: publish chat/geral Olá a todos!
publish_e2e <tópico> <destinatário> <mensagem>: Publica uma mensagem com criptografia ponta-a-ponta. A mensagem será criptografada usando uma chave simétrica derivada dos IDs do remetente e do destinatário.
Ex: publish_e2e chat/privado client2 Mensagem secreta!
ping: Envia uma mensagem de ping para o broker para verificar a conectividade.
status: Exibe o status atual da conexão e subscrições do cliente.
quit: Desconecta do broker e sai do shell interativo.
5. Geração de CSRs (Opcional)
O script generate_csr.py pode ser usado para gerar um Certificate Signing Request (CSR) e uma chave privada para uma entidade. Isso seria útil se o broker fosse uma CA completa e outras entidades (não clientes MQTT) precisassem de certificados.

bash

Run
Copy code
python generate_csr.py
O script pedirá um "Common Name" e gerará os arquivos .csr e .pem no diretório csr/.

Detalhes de Segurança
Autenticação: Utiliza certificados X.509 para autenticação mútua. O broker verifica o certificado do cliente (assinado por ele mesmo) e o cliente verifica o certificado do broker (assinado pela CA raiz).
Confidencialidade (Cliente-Broker): O envelopamento digital garante que as mensagens entre cliente e broker sejam confidenciais. A chave simétrica (AES) é gerada aleatoriamente para cada mensagem e criptografada com a chave pública do destinatário (RSA).
Confidencialidade (Ponta-a-Ponta): Para mensagens publish_e2e, uma chave simétrica compartilhada é derivada deterministicamente dos IDs do remetente e do destinatário usando SHA256. Isso permite que apenas esses dois clientes descriptografem a mensagem, mesmo que o broker a intercepte.
Integridade e Não Repúdio: As assinaturas digitais (durante a autenticação e potencialmente para mensagens) garantem a integridade e a autenticidade das comunicações.
Observações
O diretório certificates/ deve ser criado e populado com ca.crt, BrokerCertificado.crt e brokerPriv.key antes de iniciar o broker.
O broker não armazena mensagens offline. Se um cliente não estiver conectado, ele não receberá mensagens publicadas em tópicos aos quais está subscrito.
A criptografia ponta-a-ponta é baseada em uma chave simétrica derivada dos IDs dos clientes. Isso implica que a segurança dessa chave depende da confidencialidade dos IDs e da robustez do algoritmo de derivação. Em um cenário real, um protocolo de troca de chaves mais robusto (como Diffie-Hellman) seria preferível para estabelecer chaves de sessão E2E.
O timezone.utc foi adicionado para garantir que as verificações de validade temporal dos certificados sejam feitas em UTC, evitando problemas com fusos horários locais.
Licença
Este projeto é fornecido como parte de uma avaliação acadêmica e não possui uma licença formal. Sinta-se à vontade para inspecionar, modificar e usar para fins educacionais.
