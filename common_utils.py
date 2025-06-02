#!/usr/bin/env python3
"""
Common utilities for CSE Communication System
包含加密、JWT、網路通訊等共用功能 - 加密通訊版本
"""

import json
import base64
import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import jwt
import os
import struct

# 設定日誌格式
def setup_logger(name, log_file, level=logging.DEBUG):
    """設定日誌記錄器"""
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    
    # 同時輸出到控制台
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

class CryptoUtils:
    """加密工具類"""
    
    @staticmethod
    def generate_rsa_keypair():
        """生成RSA密鑰對"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_public_key(public_key):
        """序列化公鑰"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    @staticmethod
    def deserialize_public_key(pem_data):
        """反序列化公鑰"""
        return serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=default_backend()
        )
    
    @staticmethod
    def encrypt_with_rsa(public_key, data):
        """使用RSA公鑰加密"""
        encrypted = public_key.encrypt(
            data.encode('utf-8') if isinstance(data, str) else data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    
    @staticmethod
    def decrypt_with_rsa(private_key, encrypted_data):
        """使用RSA私鑰解密"""
        decrypted = private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted
    
    @staticmethod
    def sign_data(private_key, data):
        """使用私鑰簽名數據"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def verify_signature(public_key, data, signature):
        """驗證簽名"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            public_key.verify(
                base64.b64decode(signature),
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_aes_key():
        """生成AES密鑰"""
        return os.urandom(32)  # 256-bit key
    
    @staticmethod
    def encrypt_aes_gcm(key, plaintext, associated_data=None):
        """使用AES-GCM加密"""
        iv = os.urandom(12)  # 96-bit nonce for GCM
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        # 檢查輸入是否為字符串，如果是則編碼為 bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        ciphertext = encryptor.update(plaintext)
        encryptor.finalize()
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    @staticmethod
    def decrypt_aes_gcm(key, encrypted_data, associated_data=None, decode_text=True):
        """使用AES-GCM解密"""
        iv = base64.b64decode(encrypted_data['iv'])
        tag = base64.b64decode(encrypted_data['tag'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 新增參數控制是否要解碼為文字
        if decode_text:
            return plaintext.decode('utf-8')
        else:
            return plaintext
    
    @staticmethod
    def derive_key_from_passphrase(passphrase, salt=None):
        """從通關密語派生密鑰"""
        if salt is None:
            salt = b'cse_communication_salt'  # 固定salt用於廣播
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))

class SecurePasswordHandler:
    """安全的密碼處理工具"""
    
    @staticmethod
    def hash_password(password, salt=None):
        """使用 PBKDF2 進行密碼雜湊"""
        if salt is None:
            salt = os.urandom(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        password_hash = kdf.derive(password.encode('utf-8'))
        return salt, password_hash
    
    @staticmethod
    def verify_password(password, salt, password_hash):
        """驗證密碼"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        try:
            kdf.verify(password.encode('utf-8'), password_hash)
            return True
        except Exception:
            return False

class NetworkUtils:
    """網路通訊工具類 - 加密版本"""
    
    BROADCAST_PORT = 5000
    SERVICE_PORTS = {
        'server': 5001,
        'idp': 5002,
        'kacls': 5003
    }
    
    @staticmethod
    def send_broadcast(message, passphrase, port=BROADCAST_PORT):
        """發送廣播訊息"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # 加密廣播訊息
        key = CryptoUtils.derive_key_from_passphrase(passphrase)
        encrypted_msg = CryptoUtils.encrypt_aes_gcm(key, json.dumps(message))
        
        broadcast_data = {
            'encrypted': encrypted_msg,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        sock.sendto(json.dumps(broadcast_data).encode('utf-8'), ('<broadcast>', port))
        sock.close()
    
    @staticmethod
    def listen_broadcast(passphrase, callback, port=BROADCAST_PORT):
        """監聽廣播訊息"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', port))
        
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                broadcast_data = json.loads(data.decode('utf-8'))
                
                # 解密廣播訊息
                key = CryptoUtils.derive_key_from_passphrase(passphrase)
                try:
                    decrypted_msg = CryptoUtils.decrypt_aes_gcm(key, broadcast_data['encrypted'])
                    message = json.loads(decrypted_msg)
                    callback(message, addr[0])
                except Exception:
                    # 解密失敗，忽略此訊息
                    pass
                    
            except Exception as e:
                logging.error(f"Error in broadcast listener: {e}")
    
    @staticmethod
    def send_tcp_message(host, port, message, encrypt_with_public_key=None, sign_with_private_key=None):
        """發送TCP訊息 - 支援加密和簽名"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            
            # 準備要發送的訊息
            msg_to_send = message
            
            # 如果提供了私鑰，對訊息進行簽名
            if sign_with_private_key:
                msg_json = json.dumps(message)
                signature = CryptoUtils.sign_data(sign_with_private_key, msg_json)
                msg_to_send = {
                    'signed_message': msg_json,
                    'signature': signature
                }
            
            # 如果提供了公鑰，對訊息進行加密
            if encrypt_with_public_key:
                # 生成臨時 AES 密鑰
                temp_key = CryptoUtils.generate_aes_key()
                
                # 用 AES 加密訊息內容
                encrypted_content = CryptoUtils.encrypt_aes_gcm(
                    temp_key, 
                    json.dumps(msg_to_send)
                )
                
                # 用 RSA 加密 AES 密鑰
                encrypted_key = encrypt_with_public_key.encrypt(
                    temp_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                msg_to_send = {
                    'encrypted': True,
                    'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8'),
                    'encrypted_content': encrypted_content
                }
            
            # 發送訊息
            msg_bytes = json.dumps(msg_to_send).encode('utf-8')
            msg_len = struct.pack('>I', len(msg_bytes))
            sock.sendall(msg_len + msg_bytes)
            
            # 接收回應
            response_len_data = sock.recv(4)
            if len(response_len_data) != 4:
                logging.error(f"Failed to receive response length from {host}:{port}")
                return None
                
            response_len = struct.unpack('>I', response_len_data)[0]
            
            response_data = b''
            while len(response_data) < response_len:
                packet = sock.recv(response_len - len(response_data))
                if not packet:
                    logging.error(f"Connection closed while receiving response from {host}:{port}")
                    return None
                response_data += packet
            
            response_json = json.loads(response_data.decode('utf-8'))
            
            # 如果回應是加密的，解密它
            if isinstance(response_json, dict) and response_json.get('encrypted'):
                # 這裡需要調用者提供解密的私鑰
                logging.warning("Received encrypted response but decryption not implemented in client")
            
            return response_json
            
        except Exception as e:
            logging.error(f"Error sending TCP message to {host}:{port}: {e}")
            raise
        finally:
            sock.close()
    
    @staticmethod
    def start_tcp_server(port, handler, server_private_key=None, service_registry=None):
        """啟動TCP伺服器 - 支援解密"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', port))
        server_sock.listen(5)
        
        logging.info(f"TCP server started on port {port}")
        
        while True:
            client_sock, addr = server_sock.accept()
            thread = threading.Thread(
                target=NetworkUtils._handle_client_encrypted, 
                args=(client_sock, addr, handler, server_private_key, service_registry)
            )
            thread.daemon = True
            thread.start()
    
    @staticmethod
    def _handle_client_encrypted(client_sock, addr, handler, server_private_key, service_registry):
        """處理客戶端連接 - 支援解密和驗證簽名"""
        try:
            # 接收訊息長度
            len_data = client_sock.recv(4)
            if len(len_data) != 4:
                logging.error(f"Failed to receive message length from {addr}")
                return
                
            msg_len = struct.unpack('>I', len_data)[0]
            
            # 接收訊息
            msg_data = b''
            while len(msg_data) < msg_len:
                packet = client_sock.recv(min(4096, msg_len - len(msg_data)))
                if not packet:
                    logging.error(f"Connection closed while receiving data from {addr}")
                    return
                msg_data += packet
            
            received_data = json.loads(msg_data.decode('utf-8'))
            message = received_data
            sender_public_key = None
            
            # 如果訊息是加密的，先解密
            if isinstance(received_data, dict) and received_data.get('encrypted'):
                if not server_private_key:
                    raise Exception("Received encrypted message but no private key available")
                
                # 解密 AES 密鑰
                encrypted_key = base64.b64decode(received_data['encrypted_key'])
                temp_key = server_private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # 解密訊息內容
                decrypted_content = CryptoUtils.decrypt_aes_gcm(
                    temp_key,
                    received_data['encrypted_content']
                )
                message = json.loads(decrypted_content)
            
            # 如果訊息有簽名，驗證簽名
            if isinstance(message, dict) and 'signed_message' in message:
                signed_msg = message['signed_message']
                signature = message['signature']
                message = json.loads(signed_msg)
                
                # 嘗試從訊息中獲取發送者身份以驗證簽名
                if service_registry and message.get('role'):
                    sender_public_key = service_registry.get_public_key(message['role'])
                    if sender_public_key:
                        if not CryptoUtils.verify_signature(sender_public_key, signed_msg, signature):
                            raise Exception("Signature verification failed")
            
            # 處理訊息
            response = handler(message, addr[0])
            
            # 發送回應（可以根據需要加密回應）
            if response:
                response_bytes = json.dumps(response).encode('utf-8')
                response_len = struct.pack('>I', len(response_bytes))
                client_sock.sendall(response_len + response_bytes)
            
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
            import traceback
            traceback.print_exc()
            try:
                error_response = {'status': 'error', 'message': str(e)}
                error_bytes = json.dumps(error_response).encode('utf-8')
                error_len = struct.pack('>I', len(error_bytes))
                client_sock.sendall(error_len + error_bytes)
            except:
                pass
        finally:
            client_sock.close()

class JWTUtils:
    """JWT工具類"""
    
    @staticmethod
    def create_jwt(payload, private_key, algorithm='RS256'):
        """創建JWT"""
        return jwt.encode(payload, private_key, algorithm=algorithm)
    
    @staticmethod
    def verify_jwt(token, public_key, algorithms=['RS256']):
        """驗證JWT"""
        try:
            return jwt.decode(token, public_key, algorithms=algorithms)
        except jwt.InvalidTokenError:
            return None
    
    @staticmethod
    def create_3p_jwt(user_id, private_key):
        """創建3P_JWT"""
        payload = {
            'user_id': user_id,
            'type': '3P_JWT',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        return JWTUtils.create_jwt(payload, private_key)
    
    @staticmethod
    def create_b_jwt(user_id, resource_id, permissions, private_key):
        """創建B_JWT"""
        payload = {
            'user_id': user_id,
            'resource_id': resource_id,
            'permissions': permissions,
            'type': 'B_JWT',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=1)
        }
        return JWTUtils.create_jwt(payload, private_key)

class ServiceRegistry:
    """服務註冊表"""
    
    def __init__(self):
        self.services = {}
        self.public_keys = {}
        self.lock = threading.Lock()
    
    def register_service(self, role, address, public_key):
        """註冊服務"""
        with self.lock:
            self.services[role] = address
            self.public_keys[role] = public_key
            logging.info(f"Registered {role} service at {address}")
    
    def get_service(self, role):
        """獲取服務地址"""
        with self.lock:
            return self.services.get(role)
    
    def get_public_key(self, role):
        """獲取服務公鑰"""
        with self.lock:
            return self.public_keys.get(role)
    
    def is_complete(self):
        """檢查是否所有服務都已註冊"""
        with self.lock:
            required_roles = {'server', 'idp', 'kacls'}
            return all(role in self.services for role in required_roles)