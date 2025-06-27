## README: Sistema MQTT Seguro com Autenticação por Certificados e Criptografia E2E

Este projeto implementa um sistema de mensagens MQTT simplificado com foco em segurança, utilizando autenticação mútua baseada em certificados X.509 e criptografia de ponta a ponta (E2E) para as mensagens publicadas. O sistema é composto por um broker seguro e um cliente seguro, ambos desenvolvidos em Python.

### Funcionalidades

*   **Autenticação Mútua por Certificados**: Tanto o broker quanto os clientes utilizam certificados digitais para autenticar a identidade um do outro.
    *   O broker possui um certificado assinado por uma Autoridade Certificadora (CA) raiz.
    *   Os clientes solicitam certificados ao broker, que atua como uma CA intermediária para assiná-los.
*   **Envelopamento Digital (Broker-Cliente)**: A comunicação entre o broker e os clientes é protegida por um esquema de envelopamento digital, onde uma chave simétrica é usada para criptografar os dados e essa chave simétrica é criptografada com a chave pública do destinatário.
*   **Criptografia de Ponta a Ponta (E2E)**: Clientes podem enviar mensagens criptografadas de ponta a ponta para outros clientes, garantindo que apenas o remetente e o destinatário possam ler o conteúdo da mensagem. O broker não tem acesso ao conteúdo descriptografado dessas mensagens.
*   **Geração de CSR**: Um script auxiliar permite a geração de Certificate Signing Requests (CSRs) para o broker ou para clientes, facilitando o processo de emissão de certificados.
*   **Gerenciamento de Tópicos**: O broker gerencia subscrições e publicações em tópicos, encaminhando mensagens apenas para os clientes subscritos.
*   **Interface de Linha de Comando Interativa**: O cliente possui um shell interativo para facilitar testes de conexão, subscrição, publicação e ping.

### Estrutura do Projeto

```
robson/
├── certificates/
│   ├── BrokerCertificado.crt
│   ├── brokerPriv.key
│   ├── ca.crt
│   ├── client1.crt
│   ├── client1.key
│   ├── client2.crt
│   └── client2.key
├── csr/
│   ├── broker_private_key.pem
│   └── broker_request.csr
├── generate_csr.py
├── secure_broker.py
└── secure_client.py
```

*   **`certificates/`**: Diretório para armazenar todos os certificados e chaves privadas (CA, broker e clientes).
*   **`csr/`**: Diretório para armazenar Certificate Signing Requests (CSRs) e chaves privadas temporárias geradas.
*   **`generate_csr.py`**: Script para gerar um CSR e uma chave privada para uma entidade (broker ou cliente).
*   **`secure_broker.py`**: Implementação do broker MQTT seguro.
*   **`secure_client.py`**: Implementação do cliente MQTT seguro.

### Pré-requisitos

*   Python 3.x
*   Biblioteca `cryptography`: `$ pip install cryptography`

### Como Usar

#### 1. Geração de Certificados Iniciais (CA e Broker)

Antes de iniciar o broker, é necessário gerar o certificado da CA e o certificado do broker. Este projeto não inclui um script para gerar a CA e o certificado do broker diretamente, mas assume que `ca.crt`, `BrokerCertificado.crt` e `brokerPriv.key` já existem no diretório `certificates/`.

**Assunção**: Você deve ter um script `generate_ca_and_broker_certs.py` (não fornecido neste contexto) que cria:
*   `certificates/ca.crt`: O certificado da Autoridade Certificadora raiz.
*   `certificates/BrokerCertificado.crt`: O certificado do broker, assinado por `ca.crt`.
*   `certificates/brokerPriv.key`: A chave privada do broker.

Se você não tiver esses arquivos, o broker não iniciará.

#### 2. Geração de CSR para o Broker (Opcional, se você precisar de um novo CSR para o broker)

Se você precisar gerar um CSR para o broker para que ele seja assinado por uma CA externa (ou pela sua própria CA), use o script `generate_csr.py`:

```bash
python generate_csr.py
```
Será solicitado o Common Name (CN) para o CSR (ex: `Broker`). Isso criará `csr/Broker_private_key.pem` e `csr/Broker_request.csr`. Você então precisaria usar o `Broker_request.csr` para obter um certificado assinado pela sua CA e salvá-lo como `certificates/BrokerCertificado.crt`, e a chave privada como `certificates/brokerPriv.key`.

#### 3. Iniciando o Broker

Certifique-se de que os arquivos `ca.crt`, `BrokerCertificado.crt` e `brokerPriv.key` estão presentes no diretório `certificates/`.

```bash
python secure_broker.py
```
O broker iniciará e aguardará conexões na porta 8883 (padrão). Ele também imprimirá o status dos clientes conectados e tópicos a cada 10 segundos.

#### 4. Iniciando o Cliente

Para iniciar um cliente, você precisa fornecer um `client_id`.

```bash
python secure_client.py <client_id> [broker_host] [broker_port]
```
Exemplo:
```bash
python secure_client.py client1
```
ou, se o broker estiver em outra máquina:
```bash
python secure_client.py client1 192.168.1.100 8883
```

**Primeira Conexão do Cliente (Registro)**:
Na primeira vez que um cliente se conecta, se ele não tiver seus próprios certificados (`<client_id>.crt` e `<client_id>.key` no diretório `certificates/`), ele iniciará um processo de registro com o broker. O cliente gerará um par de chaves, enviará sua chave pública ao broker, e o broker assinará um certificado para o cliente. Após o registro, o cliente será instruído a reconectar para autenticar com o novo certificado.

**Conexões Subsequentes do Cliente (Autenticação)**:
Se o cliente já possui seus certificados, ele tentará autenticar-se mutuamente com o broker usando esses certificados.

#### 5. Usando a Interface Interativa do Cliente

Após conectar e autenticar, o cliente apresentará um prompt interativo:

```
=== Cliente MQTT Seguro - client1 ===
Comandos disponíveis:
 connect - Conecta ao broker
 subscribe <tópico> - Inscreve-se em um tópico
 unsubscribe <tópico> - Remove subscrição de um tópico
 publish <tópico> <mensagem> - Publica mensagem
 publish_e2e <tópico> <destinatário> <mensagem> - Publica com criptografia ponta-a-ponta
 ping - Envia um ping para o broker
 status - Mostra status da conexão
 quit - Sair

client1>
```

**Exemplos de Comandos:**

*   **Conectar:**
    ```
    client1> connect
    ```
*   **Subscrever em um tópico:**
    ```
    client1> subscribe my/topic
    ```
*   **Publicar uma mensagem normal:**
    ```
    client1> publish my/topic Hello everyone!
    ```
*   **Publicar uma mensagem com criptografia E2E:**
    (Assumindo que `client2` também está conectado e autenticado)
    ```
    client1> publish_e2e my/private/chat client2 This is a secret message for client2.
    ```
    Para que a criptografia E2E funcione, ambos os clientes (remetente e destinatário) devem ter seus certificados emitidos pelo broker e suas chaves privadas correspondentes. A chave simétrica para E2E é derivada de um material de chave comum baseado nos IDs dos clientes envolvidos.
*   **Enviar um ping:**
    ```
    client1> ping
    ```
*   **Verificar status:**
    ```
    client1> status
    ```
*   **Sair:**
    ```
    client1> quit
    ```

### Detalhes de Segurança

#### Autenticação por Certificados
O processo de autenticação mútua garante que:
*   O cliente verifica se o certificado do broker é válido e foi assinado pela CA raiz confiável.
*   O broker verifica se o certificado do cliente é válido e foi assinado por ele mesmo (o broker atua como CA intermediária para os clientes).
*   Um desafio criptográfico é usado para provar a posse da chave privada correspondente ao certificado.

#### Envelopamento Digital
A comunicação entre cliente e broker é protegida por envelopamento digital:
*   **Cliente para Broker**: O cliente criptografa a mensagem com uma chave simétrica e criptografa essa chave simétrica com a chave pública do broker. O broker usa sua chave privada para descriptografar a chave simétrica e, em seguida, a mensagem.
*   **Broker para Cliente**: O broker criptografa a mensagem com uma chave simétrica e criptografa essa chave simétrica com a chave pública do cliente. O cliente usa sua chave privada para descriptografar a chave simétrica e, em seguida, a mensagem.

#### Criptografia de Ponta a Ponta (E2E)
Para mensagens E2E, a criptografia é realizada diretamente entre os clientes, sem que o broker possa descriptografar o conteúdo:
*   **Geração da Chave E2E**: Uma chave AES é gerada usando um hash SHA256 de uma combinação ordenada dos IDs do remetente e do destinatário (ex: `hash(min(id1, id2):max(id1, id2))`). Isso garante que ambos os clientes derivem a mesma chave para a comunicação entre eles.
*   **Criptografia**: A mensagem é criptografada usando AES no modo CBC com essa chave derivada e um IV aleatório.
*   **Encaminhamento pelo Broker**: O broker recebe a mensagem E2E criptografada e a encaminha para o destinatário sem tentar descriptografá-la.
*   **Descriptografia**: O cliente destinatário usa a mesma lógica de derivação de chave para obter a chave AES e descriptografar a mensagem.

### Considerações Finais

Este projeto serve como uma demonstração de conceitos de segurança em sistemas de mensagens. Para um ambiente de produção, seriam necessárias considerações adicionais, como:
*   Revogação de certificados (CRLs ou OCSP).
*   Gerenciamento de chaves mais robusto.
*   Tratamento de erros e resiliência de rede aprimorados.
*   Escalabilidade e desempenho.
