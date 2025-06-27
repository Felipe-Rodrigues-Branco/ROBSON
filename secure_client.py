#!/usr/bin/env python3
import socket
import threading
import json
import os
import logging
import hashlib
import sys
from datetime import datetime, timedelta, timezone  # Adicionado timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecureClient:
    def __init__(self, client_id, cert_dir='certificates', broker_host='localhost', broker_port=8883):
        self.client_id = client_id
        self.cert_dir = cert_dir
        self.broker_host = broker_host
        self.broker_port = broker_port
        # Certificados
        self.ca_cert = None  # Certificado da CA raiz (para verificar o broker)
        self.client_cert = None  # Certificado do próprio cliente (assinado pelo broker)
        self.client_private_key = None  # Chave privada do cliente
        self.broker_cert = None  # Certificado do broker
        self.broker_public_key = None  # Chave pública do broker para envelopamento
        # Conexão
        self.socket = None
        self.connected = False
        self.authenticated = False
        self.running = False
        # Subscrições
        self.subscriptions = set()
        self._load_ca_certificate()  # Carrega apenas a CA inicialmente
        self._check_client_certificates()  # Verifica se o cliente já tem seus próprios certificados

    def _load_ca_certificate(self):
        """Carrega apenas o certificado da CA raiz."""
        try:
            ca_cert_path = os.path.join(self.cert_dir, 'ca.crt')
            with open(ca_cert_path, 'rb') as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())
            logger.info("Certificado da CA carregado.")
        except FileNotFoundError as e:
            logger.error(f"Erro: Arquivo ca.crt não encontrado: {e}. Certifique-se de que 'generate_ca_and_broker_certs.py' foi executado.")
            raise
        except Exception as e:
            logger.error(f"Erro ao carregar certificado da CA: {e}")
            raise

    def _check_client_certificates(self):
        """Verifica se o cliente já possui seus próprios certificados."""
        client_cert_path = os.path.join(self.cert_dir, f'{self.client_id}.crt')
        client_key_path = os.path.join(self.cert_dir, f'{self.client_id}.key')

        if os.path.exists(client_cert_path) and os.path.exists(client_key_path):
            try:
                with open(client_cert_path, 'rb') as f:
                    self.client_cert = x509.load_pem_x509_certificate(f.read())
                with open(client_key_path, 'rb') as f:
                    self.client_private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                logger.info(f"Certificados existentes para {self.client_id} carregados.")
                return True
            except Exception as e:
                logger.error(f"Erro ao carregar certificados existentes para {self.client_id}: {e}. Tentando registrar novamente.")
                self.client_cert = None
                self.client_private_key = None
                return False
        else:
            logger.info(f"Certificados para {self.client_id} não encontrados. Será necessário registrar.")
            return False

    def _save_client_certificates(self, client_cert_pem, client_key_pem):
        """Salva os certificados do cliente recebidos do broker."""
        os.makedirs(self.cert_dir, exist_ok=True)
        client_cert_path = os.path.join(self.cert_dir, f'{self.client_id}.crt')
        client_key_path = os.path.join(self.cert_dir, f'{self.client_id}.key')

        try:
            with open(client_cert_path, 'w') as f:
                f.write(client_cert_pem)
            with open(client_key_path, 'w') as f:
                f.write(client_key_pem)
            logger.info(f"Certificados para {self.client_id} salvos com sucesso.")
            self.client_cert = x509.load_pem_x509_certificate(client_cert_pem.encode())
            self.client_private_key = serialization.load_pem_private_key(client_key_pem.encode(), password=None)
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar certificados para {self.client_id}: {e}")
            return False

    def _verify_broker_certificate(self, cert_pem):
        """
        Verifica se o certificado do broker foi assinado pela CA e é válido temporalmente.
        """
        try:
            if isinstance(cert_pem, str):
                cert_pem = cert_pem.encode()
            broker_cert = x509.load_pem_x509_certificate(cert_pem)

            # 1. Verifica assinatura da CA raiz
            try:
                self.ca_cert.public_key().verify(
                    broker_cert.signature,
                    broker_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    broker_cert.signature_hash_algorithm
                )
            except Exception as e:
                return False, f"Assinatura do certificado do broker inválida pela CA raiz: {e}"

            # 2. Verifica validade temporal
            now = datetime.now(timezone.utc)  # CORREÇÃO APLICADA AQUI
            if now < broker_cert.not_valid_before_utc or now > broker_cert.not_valid_after_utc:
                return False, "Certificado do broker expirado ou ainda não válido"

            return True, broker_cert
        except Exception as e:
            return False, f"Certificado do broker inválido ou erro ao processar: {e}"

    def _create_digital_envelope(self, data):
        """
        Cria envelope digital para comunicação cliente-broker
        Implementação própria conforme especificação (não TLS)
        """
        try:
            if not self.broker_public_key:
                logger.warning("Chave pública do broker não disponível para envelopamento. Enviando dados sem envelope.")
                return data

            symmetric_key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)  # 128 bits para AES CBC

            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            pad_len = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_len] * pad_len)
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            encrypted_key = self.broker_public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            envelope = {
                'encrypted_key': base64.b64encode(encrypted_key).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_data': base64.b64encode(encrypted_data).decode()
            }
            return json.dumps(envelope).encode()
        except Exception as e:
            logger.error(f"Erro ao criar envelope digital: {e}")
            return data

    def _decrypt_digital_envelope(self, envelope_data):
        """Descriptografa envelope digital recebido do broker"""
        try:
            if isinstance(envelope_data, bytes):
                envelope_data_str = envelope_data.decode()
            else:
                envelope_data_str = envelope_data

            envelope = json.loads(envelope_data_str)

            if not all(k in envelope for k in ['encrypted_key', 'iv', 'encrypted_data']):
                logger.warning("Dados recebidos não parecem ser um envelope digital válido.")
                return None

            encrypted_key = base64.b64decode(envelope['encrypted_key'])
            symmetric_key = self.client_private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            iv = base64.b64decode(envelope['iv'])
            encrypted_data = base64.b64decode(envelope['encrypted_data'])
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            pad_len = padded_data[-1]
            return padded_data[:-pad_len]
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Dados não são um envelope JSON válido ou chaves ausentes: {e}")
            return None
        except Exception as e:
            logger.error(f"Erro ao descriptografar envelope: {e}", exc_info=True)
            return None

    def _encrypt_end_to_end(self, message_bytes, recipient_id):
        """Criptografia ponta-a-ponta entre clientes"""
        try:
            key_material = f"{min(self.client_id, recipient_id)}:{max(self.client_id, recipient_id)}".encode()
            key = hashlib.sha256(key_material).digest()

            iv = os.urandom(16)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()

            pad_len = 16 - (len(message_bytes) % 16)
            padded_message = message_bytes + bytes([pad_len] * pad_len)
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

            return {
                'iv': base64.b64encode(iv).decode(),
                'encrypted': base64.b64encode(encrypted_message).decode(),
                'sender': self.client_id,
                'e2e': True
            }
        except Exception as e:
            logger.error(f"Erro na criptografia ponta-a-ponta: {e}", exc_info=True)
            return {'message': message_bytes.decode(errors='ignore'), 'sender': self.client_id, 'e2e_error': str(e)}

    def _decrypt_end_to_end(self, encrypted_data_dict):
        """Descriptografa mensagem ponta-a-ponta"""
        try:
            sender_id = encrypted_data_dict.get('sender', 'unknown')
            key_material = f"{min(sender_id, self.client_id)}:{max(sender_id, self.client_id)}".encode()
            key = hashlib.sha256(key_material).digest()

            iv = base64.b64decode(encrypted_data_dict['iv'])
            encrypted_message = base64.b64decode(encrypted_data_dict['encrypted'])

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

            pad_len = padded_message[-1]
            return padded_message[:-pad_len]
        except Exception as e:
            logger.error(f"Erro na descriptografia ponta-a-ponta de {sender_id}: {e}", exc_info=True)
            return b"[Mensagem criptografada - erro ao descriptografar]"

    def connect(self):
        """Conecta ao broker com autenticação por certificados ou solicita um."""
        if self.connected:
            logger.info("Já conectado ao broker.")
            print("[SISTEMA] Já conectado ao broker.")
            return True

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.broker_host, self.broker_port))
            self.connected = True
            logger.info(f"Conectado ao broker {self.broker_host}:{self.broker_port}")

            if not self.client_cert or not self.client_private_key:
                logger.info(f"Cliente {self.client_id} não possui certificados. Iniciando processo de registro.")
                if not self._register_with_broker():
                    self.disconnect()
                    print("[ERRO] Falha no registro. Conexão encerrada.")
                    return False
                # Após o registro, o cliente deve fechar a conexão e tentar conectar novamente
                # para usar o novo certificado.
                self.disconnect()
                print("[SISTEMA] Certificado solicitado e salvo. Por favor, conecte-se novamente para autenticar.")
                return False
            else:
                logger.info(f"Cliente {self.client_id} possui certificados. Iniciando processo de autenticação.")
                self._authenticate()

            self.running = True
            receive_thread = threading.Thread(target=self._receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            return True
        except ConnectionRefusedError:
            logger.error(f"Conexão recusada. O broker pode não estar rodando ou o endereço/porta está incorreto: {self.broker_host}:{self.broker_port}")
            print(f"[ERRO] Conexão recusada. Verifique se o broker está online em {self.broker_host}:{self.broker_port}.")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Erro na conexão: {e}", exc_info=True)
            self.connected = False
            return False

    def _register_with_broker(self):
        """Processo de solicitação de certificado ao broker."""
        try:
            # 1. Gerar nova chave privada para o cliente
            self.client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            client_public_key_pem = self.client_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # 2. Enviar solicitação de registro com chave pública
            register_message = {
                'type': 'REGISTER_REQUEST',
                'client_id': self.client_id,
                'public_key': client_public_key_pem
            }
            self._send_raw(json.dumps(register_message).encode())
            logger.info(f"Solicitação de registro de certificado para {self.client_id} enviada.")

            # 3. Esperar pela resposta de registro
            response_data = self._receive_raw()
            if not response_data:
                logger.error("Nenhuma resposta de registro recebida do broker.")
                print("[ERRO] Falha no registro: Nenhuma resposta do broker.")
                return False

            try:
                response = json.loads(response_data.decode())
            except json.JSONDecodeError:
                logger.error("Resposta de registro inválida (não JSON).")
                print("[ERRO] Falha no registro: Resposta inválida do broker.")
                return False

            if response.get('type') == 'REGISTER_RESPONSE' and response.get('status') == 'success':
                client_cert_pem = response.get('client_certificate')
                broker_cert_pem = response.get('broker_certificate')

                if not client_cert_pem or not broker_cert_pem:
                    logger.error("Resposta de registro de sucesso incompleta.")
                    print("[ERRO] Falha no registro: Resposta de sucesso incompleta.")
                    return False

                # Verificar o certificado do broker recebido
                valid_broker_cert, broker_cert_obj = self._verify_broker_certificate(broker_cert_pem)
                if not valid_broker_cert:
                    logger.error(f"Certificado do broker recebido durante o registro é inválido: {broker_cert_obj}")
                    print(f"[ERRO] Falha no registro: Certificado do broker inválido: {broker_cert_obj}")
                    return False

                self.broker_cert = broker_cert_obj
                self.broker_public_key = broker_cert_obj.public_key()

                # Salvar o cert ificado do cliente e a chave privada
                if not self._save_client_certificates(client_cert_pem, self.client_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode()):
                    logger.error("Falha ao salvar certificados do cliente após registro.")
                    print("[ERRO] Falha no registro: Erro ao salvar certificados.")
                    return False

                logger.info(f"Registro de {self.client_id} bem-sucedido. Certificados salvos.")
                print(f"[SISTEMA] Registro de {self.client_id} bem-sucedido. Certificados salvos.")
                return True
            else:
                error_message = response.get('message', 'Erro desconhecido no registro.')
                logger.error(f"Falha no registro: {error_message}")
                print(f"[ERRO] Falha no registro: {error_message}")
                return False
        except Exception as e:
            logger.error(f"Erro durante o processo de registro: {e}", exc_info=True)
            print(f"[ERRO] Erro interno durante o registro: {e}")
            return False

    def _authenticate(self):
        """Processo de autenticação por certificados."""
        try:
            if not self.client_cert or not self.client_private_key:
                logger.error("Certificados do cliente não carregados para autenticação.")
                print("[ERRO] Certificados do cliente ausentes para autenticação.")
                return False

            # 1. Envia certificado do cliente
            cert_pem = self.client_cert.public_bytes(serialization.Encoding.PEM)
            auth_message = {
                'type': 'AUTH_REQUEST',
                'client_id': self.client_id,
                'certificate': cert_pem.decode()
            }
            self._send_raw(json.dumps(auth_message).encode())
            logger.info("Certificado do cliente enviado para autenticação.")

            # 2. Recebe desafio do broker
            response_data = self._receive_raw()
            if not response_data:
                logger.error("Nenhuma resposta de autenticação recebida do broker.")
                print("[ERRO] Nenhuma resposta de autenticação do broker.")
                return False

            try:
                response = json.loads(response_data.decode())
            except json.JSONDecodeError:
                logger.error("Resposta de autenticação inválida (não JSON).")
                print("[ERRO] Resposta de autenticação inválida do broker.")
                return False

            if response.get('type') == 'AUTH_RESPONSE' and response.get('status') == 'challenge':
                challenge = base64.b64decode(response.get('challenge'))
                broker_cert_pem = response.get('broker_certificate')

                # 3. Verifica certificado do broker
                valid_broker_cert, broker_cert_obj = self._verify_broker_certificate(broker_cert_pem)
                if not valid_broker_cert:
                    logger.error(f"Certificado do broker inválido durante autenticação: {broker_cert_obj}")
                    print(f"[ERRO] Certificado do broker inválido: {broker_cert_obj}")
                    return False

                self.broker_cert = broker_cert_obj
                self.broker_public_key = broker_cert_obj.public_key()

                # 4. Assina o desafio com a chave privada do cliente
                signature = self.client_private_key.sign(
                    challenge,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )

                # 5. Envia a resposta do desafio
                challenge_response_msg = {
                    'type': 'AUTH_CHALLENGE_RESPONSE',
                    'client_id': self.client_id,
                    'signature': base64.b64encode(signature).decode()
                }
                self._send_raw(json.dumps(challenge_response_msg).encode())
                logger.info("Resposta ao desafio enviada.")

                # 6. Espera pela confirmação final de autenticação
                final_response_data = self._receive_raw()
                if not final_response_data:
                    logger.error("Nenhuma confirmação final de autenticação recebida.")
                    print("[ERRO] Nenhuma confirmação final de autenticação.")
                    return False

                # Tenta descriptografar a resposta final (pode vir envelopada)
                final_response_decrypted = self._decrypt_digital_envelope(final_response_data)
                if final_response_decrypted:
                    final_response = json.loads(final_response_decrypted.decode())
                else:
                    final_response = json.loads(final_response_data.decode()) # Se não for envelopada

                if final_response.get('type') == 'AUTH_RESPONSE' and final_response.get('status') == 'success':
                    self.authenticated = True
                    logger.info("Autenticação bem-sucedida.")
                    print(f"[SISTEMA] Cliente {self.client_id} autenticado com sucesso!")
                    return True
                else:
                    error_message = final_response.get('message', 'Erro desconhecido na autenticação.')
                    logger.error(f"Autenticação falhou: {error_message}")
                    print(f"[ERRO] Autenticação falhou: {error_message}")
                    return False
            elif response.get('type') == 'AUTH_RESPONSE' and response.get('status') == 'failed':
                error_message = response.get('message', 'Falha desconhecida na autenticação.')
                logger.error(f"Autenticação falhou (broker rejeitou): {error_message}")
                print(f"[ERRO] Autenticação falhou: {error_message}")
                return False
            else:
                logger.error(f"Resposta inesperada do broker durante autenticação: {response}")
                print("[ERRO] Resposta inesperada do broker durante autenticação.")
                return False
        except Exception as e:
            logger.error(f"Erro durante o processo de autenticação: {e}", exc_info=True)
            print(f"[ERRO] Erro interno durante a autenticação: {e}")
            return False

    def _send_raw(self, data):
        """Envia dados brutos pelo socket com protocolo de tamanho."""
        if self.socket and self.connected:
            try:
                length = len(data)
                self.socket.sendall(length.to_bytes(4, byteorder='big') + data)
            except Exception as e:
                logger.error(f"Erro ao enviar dados brutos: {e}", exc_info=True)
                self.disconnect()
        else:
            logger.warning("Tentativa de enviar dados sem conexão ativa.")

    def _receive_raw(self):
        """Recebe dados brutos do socket com protocolo de tamanho."""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                logger.info("Conexão fechada pelo broker.")
                return None
            if len(length_bytes) != 4:
                logger.warning(f"Recebido tamanho de mensagem incompleto: {len(length_bytes)} bytes")
                return None
            length = int.from_bytes(length_bytes, byteorder='big')

            data = b''
            while len(data) < length:
                chunk = self.socket.recv(length - len(data))
                if not chunk:
                    logger.warning("Conexão fechada ou chunk vazio durante leitura da mensagem.")
                    return None
                data += chunk
            return data
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"Erro ao receber dados brutos: {e}", exc_info=True)
            self.disconnect()
            return None

    def _receive_messages(self):
        """Thread para receber mensagens do broker."""
        while self.running and self.connected:
            try:
                data = self._receive_raw()
                if not data:
                    break # Conexão fechada ou erro
                
                # Tenta descriptografar envelope se a autenticação já ocorreu
                message = None
                if self.authenticated:
                    decrypted_data = self._decrypt_digital_envelope(data)
                    if decrypted_data:
                        try:
                            message = json.loads(decrypted_data.decode())
                        except json.JSONDecodeError:
                            logger.warning("Mensagem descriptografada não é JSON válido.")
                            message = {"type": "ERROR", "message": "Mensagem recebida corrompida ou inválida."}
                    else:
                        logger.warning("Não foi possível descriptografar envelope. Tentando como JSON direto.")
                        try:
                            message = json.loads(data.decode())
                        except json.JSONDecodeError:
                            logger.error("Mensagem recebida não é JSON válido e não pôde ser descriptografada.")
                            message = {"type": "ERROR", "message": "Mensagem recebida corrompida ou inválida."}
                else: # Se ainda não autenticado, espera mensagens não envelopadas (como desafio)
                    try:
                        message = json.loads(data.decode())
                    except json.JSONDecodeError:
                        logger.error("Mensagem recebida antes da autenticação não é JSON válido.")
                        message = {"type": "ERROR", "message": "Mensagem recebida corrompida ou inválida."}

                if message:
                    self._handle_message(message)
            except Exception as e:
                logger.error(f"Erro no loop de recebimento de mensagens: {e}", exc_info=True)
                break
        self.disconnect()
        logger.info("Thread de recebimento de mensagens encerrada.")

    def _handle_message(self, message):
        """Processa mensagens recebidas do broker."""
        try:
            msg_type = message.get('type')

            if msg_type == 'PUBLISH':
                topic = message.get('topic')
                payload = message.get('payload')
                sender_id = message.get('sender', 'unknown')

                # Verifica se é mensagem ponta-a-ponta
                if isinstance(payload, dict) and payload.get('e2e'):
                    try:
                        decrypted_payload = self._decrypt_end_to_end(payload)
                        print(f"[{topic}] {sender_id}: {decrypted_payload.decode()}")
                    except Exception as e:
                        print(f"[{topic}] {sender_id}: [Mensagem criptografada E2E - erro ao descriptografar: {e}]")
                else:
                    print(f"[{topic}] {sender_id}: {payload}")
            elif msg_type == 'SUBACK':
                topic = message.get('topic')
                status = message.get('status')
                if status == 'success':
                    print(f"[SISTEMA] Inscrito no tópico: {topic}")
                    self.subscriptions.add(topic)
                else:
                    print(f"[ERRO] Falha ao inscrever-se no tópico {topic}: {message.get('message', 'Erro desconhecido')}")
            elif msg_type == 'UNSUBACK':
                topic = message.get('topic')
                status = message.get('status')
                if status == 'success':
                    print(f"[SISTEMA] Removido do tópico: {topic}")
                    self.subscriptions.discard(topic)
                else:
                    print(f"[ERRO] Falha ao remover-se do tópico {topic}: {message.get('message', 'Erro desconhecido')}")
            elif msg_type == 'PING_RESPONSE':
                logger.debug(f"Ping Response recebido: {message.get('timestamp')}")
                print(f"[SISTEMA] Ping respondido pelo broker em {message.get('timestamp')}")
            elif msg_type == 'ERROR':
                print(f"[ERRO] {message.get('message')}")
            else:
                logger.warning(f"Tipo de mensagem desconhecido recebido: {msg_type} - {message}")
                print(f"[SISTEMA] Mensagem desconhecida: {message}")
        except Exception as e:
            logger.error(f"Erro ao processar mensagem recebida: {e}", exc_info=True)

    def subscribe(self, topic):
        """Inscreve-se em um tópico."""
        if not self.authenticated:
            print("[ERRO] Cliente não autenticado. Conecte-se e autentique-se primeiro.")
            return
        try:
            message = {
                'type': 'SUBSCRIBE',
                'topic': topic,
                'client_id': self.client_id
            }
            data = self._create_digital_envelope(json.dumps(message).encode())
            if data:
                self._send_raw(data)
            else:
                logger.error("Falha ao criar envelope para SUBSCRIBE.")
                print("[ERRO] Falha ao enviar solicitação de subscrição.")
        except Exception as e:
            logger.error(f"Erro ao se inscrever no tópico {topic}: {e}", exc_info=True)
            print(f"[ERRO] Erro ao se inscrever no tópico {topic}.")

    def unsubscribe(self, topic):
        """Remove subscrição de um tópico."""
        if not self.authenticated:
            print("[ERRO] Cliente não autenticado. Conecte-se e autentique-se primeiro.")
            return
        try:
            message = {
                'type': 'UNSUBSCRIBE',
                'topic': topic,
                'client_id': self.client_id
            }
            data = self._create_digital_envelope(json.dumps(message).encode())
            if data:
                self._send_raw(data)
            else:
                logger.error("Falha ao criar envelope para UNSUBSCRIBE.")
                print("[ERRO] Falha ao enviar solicitação de remoção de subscrição.")
        except Exception as e:
            logger.error(f"Erro ao remover subscrição do tópico {topic}: {e}", exc_info=True)
            print(f"[ERRO] Erro ao remover subscrição do tópico {topic}.")

    def publish(self, topic, message, end_to_end=False, recipient_id=None):
        """Publica mensagem em um tópico."""
        if not self.authenticated:
            print("[ERRO] Cliente não autenticado. Conecte-se e autentique-se primeiro.")
            return
        try:
            payload_to_send = message
            if end_to_end and recipient_id:
                # Criptografia ponta-a-ponta
                payload_to_send = self._encrypt_end_to_end(message.encode(), recipient_id)
            elif end_to_end and not recipient_id:
                print("[ERRO] Para criptografia ponta-a-ponta, o ID do destinatário é obrigatório.")
                return

            publish_message = {
                'type': 'PUBLISH',
                'topic': topic,
                'payload': payload_to_send,
                'client_id': self.client_id
            }
            data = self._create_digital_envelope(json.dumps(publish_message).encode())
            if data:
                self._send_raw(data)
            else:
                logger.error("Falha ao criar envelope para PUBLISH.")
                print("[ERRO] Falha ao enviar mensagem.")
        except Exception as e:
            logger.error(f"Erro ao publicar no tópico {topic}: {e}", exc_info=True)
            print(f"[ERRO] Erro ao publicar no tópico {topic}.")

    def ping(self):
        """Envia uma mensagem de ping para o broker."""
        if not self.authenticated:
            print("[ERRO] Cliente não autenticado. Conecte-se e autentique-se primeiro.")
            return
        try:
            ping_message = {
                'type': 'PING',
                'client_id': self.client_id
            }
            data = self._create_digital_envelope(json.dumps(ping_message).encode())
            if data:
                self._send_raw(data)
            else:
                logger.error("Falha ao criar envelope para PING.")
                print("[ERRO] Falha ao enviar ping.")
        except Exception as e:
            logger.error(f"Erro ao enviar ping: {e}", exc_info=True)
            print(f"[ERRO] Erro ao enviar ping.")

    def disconnect(self):
        """Desconecta do broker."""
        self.running = False
        self.authenticated = False
        self.connected = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
            except Exception as e:
                logger.error(f"Erro ao fechar socket: {e}")
            self.socket = None
        logger.info(f"Cliente {self.client_id} desconectado.")
        print(f"[SISTEMA] Cliente {self.client_id} desconectado.")

    def interactive_shell(self):
        """Interface interativa para testes."""
        print(f"\n=== Cliente MQTT Seguro - {self.client_id} ===")
        print("Comandos disponíveis:")
        print(" connect - Conecta ao broker")
        print(" subscribe <tópico> - Inscreve-se em um tópico")
        print(" unsubscribe <tópico> - Remove subscrição de um tópico")
        print(" publish <tópico> <mensagem> - Publica mensagem")
        print(" publish_e2e <tópico> <destinatário> <mensagem> - Publica com criptografia ponta-a-ponta")
        print(" ping - Envia um ping para o broker")
        print(" status - Mostra status da conexão")
        print(" quit - Sair")
        print()
        while True:
            try:
                command_line = input(f"{self.client_id}> ").strip()
                if not command_line:
                    continue
                command = command_line.split(maxsplit=1) # Divide apenas no primeiro espaço
                cmd = command[0].lower()
                args = command[1] if len(command) > 1 else ""

                if cmd == 'connect':
                    self.connect()
                elif cmd == 'subscribe':
                    if not args:
                        print("Uso: subscribe <tópico>")
                        continue
                    self.subscribe(args)
                elif cmd == 'unsubscribe':
                    if not args:
                        print("Uso: unsubscribe <tópico>")
                        continue
                    self.unsubscribe(args)
                elif cmd == 'publish':
                    parts = args.split(maxsplit=1)
                    if len(parts) < 2:
                        print("Uso: publish <tópico> <mensagem>")
                        continue
                    topic = parts[0]
                    message = parts[1]
                    self.publish(topic, message)
                elif cmd == 'publish_e2e':
                    parts = args.split(maxsplit=2)
                    if len(parts) < 3:
                        print("Uso: publish_e2e <tópico> <destinatário> <mensagem>")
                        continue
                    topic = parts[0]
                    recipient = parts[1]
                    message = parts[2]
                    self.publish(topic, message, end_to_end=True, recipient_id=recipient)
                elif cmd == 'ping':
                    self.ping()
                elif cmd == 'status':
                    print(f"Conectado: {self.connected}")
                    print(f"Autenticado: {self.authenticated}")
                    print(f"Inscrições: {list(self.subscriptions)}")
                elif cmd == 'quit':
                    self.disconnect()
                    print("Tchau!")
                    break
                else:
                    print("Comando não reconhecido")
            except KeyboardInterrupt:
                print("\nSaindo...")
                self.disconnect()
                break
            except Exception as e:
                print(f"Erro inesperado no shell interativo: {e}")
                logger.error(f"Erro no shell interativo: {e}", exc_info=True)

def main():
    """Função principal."""
    if len(sys.argv) < 2:
        print("Uso: python secure_client.py <client_id> [broker_host] [broker_port]")
        print("Exemplo: python secure_client.py client1")
        sys.exit(1)

    client_id = sys.argv[1]
    broker_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    broker_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8883
    
    # Garante que o diretório de certificados existe
    cert_dir = 'certificates'
    os.makedirs(cert_dir, exist_ok=True)

    try:
        client = SecureClient(client_id, cert_dir, broker_host, broker_port)
        client.interactive_shell()
    except Exception as e:
        logger.error(f"Erro fatal na inicialização do cliente: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
