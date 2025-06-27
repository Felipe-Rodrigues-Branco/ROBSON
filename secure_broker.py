#!/usr/bin/env python3

import socket
import threading
import json
import os
import logging
import hashlib
from datetime import datetime, timedelta, timezone  # Adicionado timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureBroker:
    def __init__(self, host='localhost', port=8883, cert_dir='certificates'):
        self.host = host
        self.port = port
        self.cert_dir = cert_dir
        # Estruturas de dados do broker
        self.clients = {}  # client_socket -> client_info
        self.topics = {}  # topic -> set of client_sockets
        self.authenticated_clients = {}  # client_id -> client_socket
        # Certificados do broker
        self.ca_cert = None
        self.broker_cert = None
        self.broker_private_key = None
        # Socket do servidor
        self.server_socket = None
        self.running = False
        self._load_certificates()

    def _load_certificates(self):
        """Carrega os certificados necessários do broker"""
        try:
            # Certificado da CA (Autoridade Certificadora - Professor)
            ca_cert_path = os.path.join(self.cert_dir, 'ca.crt')
            with open(ca_cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())

            # Certificado do broker (assinado pela CA)
            broker_cert_path = os.path.join(self.cert_dir, 'BrokerCertificado.crt')
            with open(broker_cert_path, 'rb') as f:
                self.broker_cert = x509.load_pem_x509_certificate(f.read())

            # Chave privada do broker
            broker_key_path = os.path.join(self.cert_dir, 'brokerPriv.key')
            with open(broker_key_path, 'rb') as f:
                self.broker_private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            logger.info("Certificados do broker carregados com sucesso")
        except FileNotFoundError as e:
            logger.error(f"Erro: Arquivo de certificado do broker não encontrado: {e}. Certifique-se de que 'generate_ca_and_broker_certs.py' foi executado.")
            raise
        except Exception as e:
            logger.error(f"Erro ao carregar certificados do broker: {e}")
            raise

    def _verify_client_certificate(self, cert_data):
        """
        Verifica se o certificado do cliente foi assinado pelo BROKER e é válido temporalmente.
        O broker age como uma CA intermediária para os clientes.
        """
        try:
            if isinstance(cert_data, str):
                cert_data = cert_data.encode()
            client_cert = x509.load_pem_x509_certificate(cert_data)

            # 1. Verifica se o emissor do certificado do cliente é o broker
            if client_cert.issuer != self.broker_cert.subject:
                return False, f"Certificado do cliente não foi emitido pelo broker. Emissor: {client_cert.issuer.rfc4514_string()}"

            # 2. Verifica a assinatura do certificado do cliente usando a chave pública do broker
            try:
                self.broker_cert.public_key().verify(
                    client_cert.signature,
                    client_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    client_cert.signature_hash_algorithm
                )
            except Exception as e:
                return False, f"Assinatura do certificado do cliente inválida pela chave pública do broker: {e}"

            # 3. Verifica validade temporal
            now = datetime.now(timezone.utc)  
            if now < client_cert.not_valid_before_utc or now > client_cert.not_valid_after_utc:
                return False, "Certificado do cliente expirado ou ainda não válido"

            return True, client_cert
        except Exception as e:
            return False, f"Certificado inválido ou erro ao processar: {e}"

    def _create_digital_envelope(self, data, public_key_recipient):
        """
        Implementa envelopamento digital próprio (não TLS)
        Conforme especificado na avaliação
        """
        try:
            # Gera chave simétrica AES-256
            symmetric_key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)  # 128 bits para AES CBC

            # Criptografa dados com AES
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            # Padding PKCS7
            pad_len = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_len] * pad_len)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Criptografa chave simétrica com chave pública do destinatário
            encrypted_key = public_key_recipient.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Cria envelope digital
            envelope = {
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode()
            }
            return json.dumps(envelope).encode()
        except Exception as e:
            logger.error(f"Erro ao criar envelope digital: {e}")
            return None

    def _decrypt_digital_envelope(self, envelope_data):
        """Descriptografa envelope digital recebido do cliente"""
        try:
            envelope = json.loads(envelope_data.decode())
            # Descriptografa chave simétrica
            encrypted_key = base64.b64decode(envelope['encrypted_key'])
            symmetric_key = self.broker_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # Descriptografa dados
            iv = base64.b64decode(envelope['iv'])
            encrypted_data = base64.b64decode(envelope['encrypted_data'])
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            # Remove padding PKCS7
            pad_len = padded_data[-1]
            data = padded_data[:-pad_len]
            return data
        except Exception as e:
            logger.error(f"Erro ao descriptografar envelope: {e}")
            return None

    def _send_message(self, client_socket, data):
        """Envia mensagem para cliente com protocolo de tamanho"""
        try:
            length = len(data)
            length_bytes = length.to_bytes(4, byteorder='big')
            client_socket.sendall(length_bytes + data)
            return True
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
            return False

    def _receive_message(self, client_socket):
        """Recebe mensagem do cliente com protocolo de tamanho"""
        try:
            # Lê tamanho da mensagem
            length_bytes = client_socket.recv(4)
            if not length_bytes:  # Conexão fechada ou erro
                return None
            if len(length_bytes) != 4:  # Dados incompletos
                logger.warning(f"Recebido tamanho de mensagem incompleto: {len(length_bytes)} bytes")
                return None
            length = int.from_bytes(length_bytes, byteorder='big')

            # Lê mensagem completa
            data = b''
            while len(data) < length:
                chunk = client_socket.recv(length - len(data))
                if not chunk:  # Conexão fechada ou erro durante a leitura do corpo
                    logger.warning("Conexão fechada ou chunk vazio durante leitura da mensagem.")
                    return None
                data += chunk
            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Erro ao receber mensagem: {e}")
            return None

    def _generate_client_certificate(self, client_id, client_public_key_pem):
        """
        Gera e assina um certificado para o cliente usando a chave privada do broker.
        O broker age como uma CA intermediária para os clientes.
        """
        try:
            client_public_key = serialization.load_pem_public_key(client_public_key_pem)

            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SC"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Lages"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IFSC"),
                x509.NameAttribute(NameOID.COMMON_NAME, client_id),
            ])

            # O issuer do certificado do cliente será o broker
            issuer = self.broker_cert.subject

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(client_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc))  # Certificado válido a partir de agora
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))  # Válido por 1 ano
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.broker_private_key, hashes.SHA256())  # Assinado pela chave privada do broker
            )
            logger.info(f"Certificado para {client_id} gerado e assinado pelo broker.")

            # Salvar o certificado em um arquivo
            client_cert_path = os.path.join(self.cert_dir, f'{client_id}.crt')
            with open(client_cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Salvar a chave privada do cliente
            client_key_path = os.path.join(self.cert_dir, f'{client_id}.key')
            with open(client_key_path, 'wb') as f:
                f.write(client_public_key_pem)

            logger.info(f"Certificado e chave privada para {client_id} salvos com sucesso.")
            return cert.public_bytes(serialization.Encoding.PEM).decode()
        except Exception as e:
            logger.error(f"Erro ao gerar certificado para {client_id}: {e}")
            return None

    def _authenticate_client(self, client_socket, client_address):
        """
        Realiza autenticação mútua por certificados.
        Agora também lida com a emissão de certificados para novos clientes.
        """
        try:
            logger.info(f"Iniciando autenticação para {client_address}")

            # 1. Recebe solicitação de autenticação/registro do cliente
            auth_data = self._receive_message(client_socket)
            if not auth_data:
                logger.warning(f"Nenhum dado de autenticação/registro recebido de {client_address}")
                return False, None
            try:
                auth_request = json.loads(auth_data.decode())
            except json.JSONDecodeError:
                logger.warning(f"Dados de autenticação/registro inválidos (não JSON) de {client_address}")
                return False, None

            client_id = auth_request.get('client_id')
            if not client_id:
                logger.warning(f"Solicitação sem client_id de {client_address}")
                return False, None

            request_type = auth_request.get('type')

            if request_type == 'REGISTER_REQUEST':
                logger.info(f"Recebida solicitação de registro de certificado para {client_id} de {client_address}")
                client_public_key_pem = auth_request.get('public_key')
                if not client_public_key_pem:
                    logger.warning(f"Solicitação de registro de {client_id} sem chave pública.")
                    fail_msg = {'type': 'REGISTER_RESPONSE', 'status': 'failed', 'message': 'Chave pública ausente.'}
                    self._send_message(client_socket, json.dumps(fail_msg).encode())
                    return False, None

                signed_client_cert_pem = self._generate_client_certificate(client_id, client_public_key_pem.encode())
                if signed_client_cert_pem:
                    success_msg = {
                        'type': 'REGISTER_RESPONSE',
                        'status': 'success',
                        'client_certificate': signed_client_cert_pem,
                        'broker_certificate': self.broker_cert.public_bytes(serialization.Encoding.PEM).decode()
                    }
                    self._send_message(client_socket, json.dumps(success_msg).encode())
                    logger.info(f"Certificado emitido e enviado para {client_id}. Cliente deve reconectar para autenticar.")
                    return False, None  # Cliente deve reconectar com o novo certificado
                else:
                    fail_msg = {'type': 'REGISTER_RESPONSE', 'status': 'failed', 'message': 'Falha ao emitir certificado.'}
                    self._send_message(client_socket, json.dumps(fail_msg).encode())
                    return False, None

            elif request_type == 'AUTH_REQUEST':
                logger.info(f"Recebida solicitação de autenticação para {client_id} de {client_address}")
                client_cert_pem = auth_request.get('certificate')
                if not client_cert_pem:
                    logger.warning(f"Solicitação de autenticação de {client_id} sem certificado.")
                    fail_msg = {'type': 'AUTH_RESPONSE', 'status': 'failed', 'message': 'Certificado ausente.'}
                    self._send_message(client_socket, json.dumps(fail_msg).encode())
                    return False, None

                # 2. Verifica certificado do cliente
                valid, client_cert_or_error = self._verify_client_certificate(client_cert_pem)
                if not valid:
                    logger.warning(f"Certificado inválido para {client_id} ({client_address}): {client_cert_or_error}")
                    fail_msg = {'type': 'AUTH_RESPONSE', 'status': 'failed', 'message': client_cert_or_error}
                    self._send_message(client_socket, json.dumps(fail_msg).encode())
                    return False, None
                client_cert = client_cert_or_error  # Se valid for True, é o certificado

                # 3. Envia desafio criptográfico e certificado do broker
                challenge = os.urandom(32)
                broker_cert_pem = self.broker_cert.public_bytes(serialization.Encoding.PEM).decode()
                challenge_msg = {
                    'type': 'AUTH_RESPONSE',
                    'status': 'challenge',  # Indica que é um desafio, não sucesso final,
                    'challenge': base64.b64encode(challenge).decode(),
                    'broker_certificate': broker_cert_pem
                }
                if not self._send_message(client_socket, json.dumps(challenge_msg).encode()):
                    logger.error(f"Falha ao enviar desafio para {client_id}")
                    return False, None

                # 4. Recebe resposta do desafio
                response_data = self._receive_message(client_socket)
                if not response_data:
                    logger.warning(f"Nenhuma resposta ao desafio recebida de {client_id}")
                    return False, None

                try:
                    challenge_response = json.loads(response_data.decode())
                except json.JSONDecodeError:
                    logger.warning(f"Resposta ao desafio inválida (não JSON) de {client_id}")
                    return False, None

                if challenge_response.get('type') != 'AUTH_CHALLENGE_RESPONSE':  # Novo tipo para a resposta do desafio
                    logger.warning(f"Tipo de mensagem de resposta ao desafio inesperado: {challenge_response.get('type')}")
                    return False, None

                # 5. Verifica assinatura do desafio
                signature = base64.b64decode(challenge_response.get('signature', ''))
                client_public_key = client_cert.public_key()
                try:
                    client_public_key.verify(
                        signature,
                        challenge,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
                except Exception as e:
                    logger.warning(f"Assinatura do desafio inválida para {client_id}: {e}")
                    fail_msg = {'type': 'AUTH_RESPONSE', 'status': 'failed', 'message': 'Assinatura do desafio inválida'}
                    self._send_message(client_socket, json.dumps(fail_msg).encode())
                    return False, None

                # 6. Autentica cliente e armazena informações
                self.clients[client_socket] = {
                    'id': client_id,
                    'address': client_address,
                    'certificate': client_cert,
                    'public_key': client_public_key,
                    'subscriptions': set()
                }
                self.authenticated_clients[client_id] = client_socket

                # 7. Envia confirmação de autenticação
                success_msg = {
                    'type': 'AUTH_RESPONSE',
                    'status': 'success',
                    'message': 'Autenticação bem-sucedida'
                }
                # Envia com envelope digital (agora que a chave pública do cliente é confiável)
                envelope = self._create_digital_envelope(
                    json.dumps(success_msg).encode(),
                    client_public_key
                )
                if envelope:
                    self._send_message(client_socket, envelope)
                else:
                    logger.error(f"Falha ao criar envelope para AUTH_SUCCESS para {client_id}. Enviando sem envelopamento.")
                    self._send_message(client_socket, json.dumps(success_msg).encode())

                logger.info(f"Cliente {client_id} autenticado com sucesso")
                return True, client_id
            else:
                logger.warning(f"Tipo de solicitação desconhecido de {client_id}: {request_type}")
                fail_msg = {'type': 'ERROR', 'message': 'Tipo de solicitação desconhecido.'}
                self._send_message(client_socket, json.dumps(fail_msg).encode())
                return False, None

        except Exception as e:
            logger.error(f"Erro geral na autenticação para {client_address}: {e}", exc_info=True)
            try:
                fail_msg = {'type': 'AUTH_RESPONSE', 'status': 'failed', 'message': f"Erro interno do broker durante autenticação: {e}"}
                self._send_message(client_socket, json.dumps(fail_msg).encode())
            except Exception as send_e:
                logger.error(f"Erro ao enviar mensagem de falha de autenticação: {send_e}")
            return False, None

    def _handle_client_message(self, client_socket, message_data):
        """
        Processa mensagens do cliente
        Importante: Broker só lê cabeçalhos, não payloads criptografados E2E
        """
        try:
            client_info = self.clients.get(client_socket)
            if not client_info:
                logger.warning(f"Mensagem recebida de socket não autenticado: {client_socket.getpeername()}")
                return False

            client_id = client_info['id']
            message = None
            # Tenta descriptografar envelope se necessário
            try:
                decrypted_data = self._decrypt_digital_envelope(message_data)
                if decrypted_data:
                    message = json.loads(decrypted_data.decode())
                else:
                    # Se não conseguiu descriptografar, tenta como JSON direto (pode ser mensagem de erro ou não envelopada)
                    message = json.loads(message_data.decode())
            except Exception as e:
                logger.warning(f"Não foi possível descriptografar ou decodificar mensagem de {client_id}: {e}. Tentando como JSON direto.")
                try:
                    message = json.loads(message_data.decode())
                except json.JSONDecodeError:
                    logger.error(f"Mensagem inválida (não JSON) de {client_id}: {message_data}")
                    return False

            if not message:
                logger.warning(f"Mensagem vazia ou inválida de {client_id}")
                return False

            msg_type = message.get('type')
            if msg_type == 'SUBSCRIBE':
                return self._handle_subscribe(client_socket, message)
            elif msg_type == 'UNSUBSCRIBE':
                return self._handle_unsubscribe(client_socket, message)
            elif msg_type == 'PUBLISH':
                return self._handle_publish(client_socket, message)
            elif msg_type == 'PING':
                return self._handle_ping(client_socket, message)
            else:
                logger.warning(f"Tipo de mensagem desconhecido de {client_id}: {msg_type}")
                return True
        except Exception as e:
            logger.error(f"Erro ao processar mensagem de {client_socket.getpeername()}: {e}", exc_info=True)
            return False

    def _handle_subscribe(self, client_socket, message):
        """Gerencia subscrição a tópicos"""
        try:
            topic = message.get('topic')
            client_info = self.clients.get(client_socket)
            if not client_info:
                logger.warning(f"Cliente não encontrado para subscrição: {client_socket.getpeername()}")
                return False
            client_id = client_info['id']

            if not topic:
                logger.warning(f"Solicitação de subscrição sem tópico de {client_id}")
                return True

            # Adiciona cliente ao tópico
            if topic not in self.topics:
                self.topics[topic] = set()
            self.topics[topic].add(client_socket)
            client_info['subscriptions'].add(topic)

            # Confirma subscrição
            response = {
                'type': 'SUBACK',
                'topic': topic,
                'status': 'success'
            }
            envelope = self._create_digital_envelope(
                json.dumps(response).encode(),
                client_info['public_key']
            )
            if envelope:
                self._send_message(client_socket, envelope)
            else:
                logger.error(f"Falha ao criar envelope para SUBACK para {client_id}. Enviando sem envelopamento.")
                self._send_message(client_socket, json.dumps(response).encode())

            logger.info(f"Cliente {client_id} subscrito ao tópico '{topic}'")
            return True
        except Exception as e:
            logger.error(f"Erro na subscrição para {client_socket.getpeername()}: {e}", exc_info=True)
            return False

    def _handle_unsubscribe(self, client_socket, message):
        """Gerencia remoção de subscrição"""
        try:
            topic = message.get('topic')
            client_info = self.clients.get(client_socket)
            if not client_info:
                logger.warning(f"Cliente não encontrado para remoção de subscrição: {client_socket.getpeername()}")
                return False
            client_id = client_info['id']

            if not topic:
                logger.warning(f"Solicitação de remoção de subscrição sem tópico de {client_id}")
                return True

            # Remove cliente do tópico
            if topic in self.topics:
                self.topics[topic].discard(client_socket)
                if not self.topics[topic]:  # Se não há mais assinantes, remove o tópico
                    del self.topics[topic]
            client_info['subscriptions'].discard(topic)

            # Confirma remoção
            response = {
                'type': 'UNSUBACK',
                'topic': topic,
                'status': 'success'
            }
            envelope = self._create_digital_envelope(
                json.dumps(response).encode(),
                client_info['public_key']
            )
            if envelope:
                self._send_message(client_socket, envelope)
            else:
                logger.error(f"Falha ao criar envelope para UNSUBACK para {client_id}. Enviando sem envelopamento.")
                self._send_message(client_socket, json.dumps(response).encode())

            logger.info(f"Cliente {client_id} removido do tópico '{topic}'")
            return True
        except Exception as e:
            logger.error(f"Erro na remoção de subscrição para {client_socket.getpeername()}: {e}", exc_info=True)
            return False

    def _handle_publish(self, client_socket, message):
        """
        Gerencia publicação de mensagens
        IMPORTANTE: Broker não consegue descriptografar payload E2E
        """
        try:
            topic = message.get('topic')
            payload = message.get('payload')  # Pode estar criptografado E2E
            client_info = self.clients.get(client_socket)
            if not client_info:
                logger.warning(f"Cliente não encontrado para publicação: {client_socket.getpeername()}")
                return False
            client_id = client_info['id']

            if not topic:
                logger.warning(f"Solicitação de publicação sem tópico de {client_id}")
                return True

            # Verifica se tópico existe e tem assinantes
            if topic not in self.topics or not self.topics[topic]:
                logger.info(f"Tópico '{topic}' não possui assinantes ou não existe. Mensagem de {client_id} descartada.")
                # Opcional: enviar um PUBACK ou erro para o publicador
                return True

            # Prepara mensagem para encaminhamento
            # Broker mantém payload original (não consegue descriptografar E2E)
            forward_message = {
                'type': 'PUBLISH',
                'topic': topic,
                'sender': client_id,
                'payload': payload,  # Mantém criptografia E2E se existir
                'timestamp': datetime.now().isoformat()
            }

            # Encaminha para todos os assinantes (exceto o próprio publicador)
            subscribers = self.topics[topic].copy()
            subscribers.discard(client_socket)  # Não envia de volta para o publicador

            successful_deliveries = 0
            for subscriber in subscribers:
                try:
                    subscriber_info = self.clients.get(subscriber)
                    if subscriber_info:
                        envelope = self._create_digital_envelope(
                            json.dumps(forward_message).encode(),
                            subscriber_info['public_key']
                        )
                        if envelope and self._send_message(subscriber, envelope):
                            successful_deliveries += 1
                        else:
                            logger.warning(f"Falha ao enviar mensagem envelopada para assinante {subscriber_info['id']}")
                    else:
                        logger.warning(f"Informações do assinante não encontradas para socket {subscriber.getpeername()}")
                except Exception as e:
                    logger.error(f"Erro ao encaminhar mensagem para assinante {subscriber.getpeername()}: {e}", exc_info=True)
                    self._cleanup_client(subscriber) # Limpa cliente com erro de envio

            logger.info(
                f"Mensagem de {client_id} no tópico '{topic}' "
                f"entregue a {successful_deliveries} assinantes"
            )
            return True
        except Exception as e:
            logger.error(f"Erro na publicação de {client_socket.getpeername()}: {e}", exc_info=True)
            return False

    def _handle_ping(self, client_socket, message):
        """Responde a ping do cliente"""
        try:
            client_info = self.clients.get(client_socket)
            if not client_info:
                logger.warning(f"Cliente não encontrado para ping: {client_socket.getpeername()}")
                return False

            response = {
                'type': 'PING_RESPONSE',
                'timestamp': datetime.now().isoformat()
            }
            envelope = self._create_digital_envelope(
                json.dumps(response).encode(),
                client_info['public_key']
            )
            if envelope:
                self._send_message(client_socket, envelope)
            else:
                logger.error(f"Falha ao criar envelope para PING_RESPONSE para {client_info['id']}. Enviando sem envelopamento.")
                self._send_message(client_socket, json.dumps(response).encode())
            logger.debug(f"Ping respondido para {client_info['id']}")
            return True
        except Exception as e:
            logger.error(f"Erro ao responder ping para {client_socket.getpeername()}: {e}", exc_info=True)
            return False

    def _handle_client_connection(self, client_socket, client_address):
        """Gerencia conexão completa do cliente"""
        try:
            # Autenticação
            authenticated, client_id = self._authenticate_client(client_socket, client_address)
            if not authenticated:
                logger.warning(f"Autenticação falhou para {client_address}. Fechando conexão.")
                client_socket.close()
                return

            logger.info(f"Cliente {client_id} conectado de {client_address}")

            # Loop principal de comunicação
            while self.running:
                try:
                    message_data = self._receive_message(client_socket)
                    if message_data is None:  # Conexão fechada ou erro na leitura
                        logger.info(f"Conexão com {client_id} ({client_address}) encerrada pelo cliente ou erro de leitura.")
                        break
                    if not self._handle_client_message(client_socket, message_data):
                        logger.warning(f"Falha ao processar mensagem de {client_id}. Encerrando conexão.")
                        break
                except socket.timeout:
                    # O timeout é normal, apenas continua esperando por dados
                    continue
                except Exception as e:
                    logger.error(f"Erro na comunicação com {client_id} ({client_address}): {e}", exc_info=True)
                    break
        except Exception as e:
            logger.error(f"Erro na conexão {client_address}: {e}", exc_info=True)
        finally:
            self._cleanup_client(client_socket)

    def _cleanup_client(self, client_socket):
        """Remove cliente e limpa recursos"""
        try:
            if client_socket in self.clients:
                client_info = self.clients[client_socket]
                client_id = client_info['id']
                # Remove de tópicos
                for topic in client_info['subscriptions'].copy():
                    if topic in self.topics:
                        self.topics[topic].discard(client_socket)
                        if not self.topics[topic]:
                            del self.topics[topic]
                # Remove registros
                del self.clients[client_socket]
                if client_id in self.authenticated_clients and self.authenticated_clients[client_id] == client_socket:
                    del self.authenticated_clients[client_id]
                logger.info(f"Cliente {client_id} desconectado e recursos limpos")
            client_socket.close()
        except Exception as e:
            logger.error(f"Erro na limpeza do cliente {client_socket.getpeername()}: {e}", exc_info=True)

    def start(self):
        """Inicia o broker"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.settimeout(1.0)  # Timeout para accept para permitir verificação de self.running
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.running = True
            logger.info(f" 🚀   Broker MQTT Seguro iniciado em {self.host}:{self.port}")
            logger.info("Aguardando conexões de clientes...")
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_socket.settimeout(60.0)  # Timeout para operações de socket do cliente
                    # Thread para cada cliente
                    client_thread = threading.Thread(
                        target=self._handle_client_connection,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue  # Apenas re-verifica self.running
                except Exception as e:
                    if self.running: # Só loga se o broker ainda estiver rodando
                        logger.error(f"Erro ao aceitar conexão: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Erro fatal no broker: {e}", exc_info=True)
        finally:
            self.stop()

    def stop(self):
        """Para o broker graciosamente"""
        logger.info("Parando broker...")
        self.running = False
        # Fecha conexões de clientes
        for client_socket in list(self.clients.keys()):
            self._cleanup_client(client_socket)
        # Fecha socket do servidor
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Erro ao fechar socket do servidor: {e}")
        logger.info("Broker parado")

    def print_status(self):
        """Mostra status atual do broker"""
        print(f"\n=== STATUS DO BROKER ===")
        print(f"Clientes conectados: {len(self.clients)}")
        print(f"Tópicos ativos: {len(self.topics)}")
        if self.clients:
            print("\nClientes:")
            for socket, info in self.clients.items():
                subs = ', '.join(info['subscriptions']) if info['subscriptions'] else 'Nenhuma'
                print(f" - {info['id']} ({info['address'][0]}:{info['address'][1]}) - Subscrições: {subs}")
        if self.topics:
            print("\nTópicos:")
            for topic, subscribers in self.topics.items():
                subscriber_ids = [self.clients[s]['id'] for s in subscribers if s in self.clients]
                print(f" - {topic}: {len(subscribers)} assinantes ({', '.join(subscriber_ids)})")

def main():
    """Função principal"""
    print("=== BROKER MQTT SEGURO ===")
    print("Implementação para Avaliação 3 - Redes de Computadores II")
    print()
    # Verifica certificados
    cert_dir = 'certificates'
    required_files = ['ca.crt', 'BrokerCertificado.crt', 'brokerPriv.key']
    for filename in required_files:
        filepath = os.path.join(cert_dir, filename)
        if not os.path.exists(filepath):
            print(f" ❌   Arquivo não encontrado: {filepath}")
            print("\nCertifique-se de que o diretório 'certificates' contém:")
            print(" - ca.crt (certificado da CA)")
            print(" - BrokerCertificado.crt (certificado do broker)")
            print(" - brokerPriv.key (chave privada do broker)")
            print("\nExecute 'python generate_ca_and_broker_certs.py' primeiro para gerar os certificados.")
            return

    try:
        broker = SecureBroker()
        # Thread para mostrar status
        def status_thread_func():
            import time
            while broker.running:
                time.sleep(10)
                broker.print_status()
        status_monitor = threading.Thread(target=status_thread_func, daemon=True)
        status_monitor.start()

        print("Pressione Ctrl+C para parar o broker")
        broker.start()
    except KeyboardInterrupt:
        print("\n\nParando broker...")
    except Exception as e:
        logger.error(f"Erro durante a execução principal do broker: {e}", exc_info=True)
    finally:
        if 'broker' in locals() and broker.running:
            broker.stop()

if __name__ == "__main__":
    main()
