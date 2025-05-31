 #!/usr/bin/env python3
"""
Common utilities for CSE Communication System
包含加密、JWT、網路通訊等共用功能
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
        return decrypted.decode('utf-8')
    
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

class NetworkUtils:
    """網路通訊工具類"""
    
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
    def send_tcp_message(host, port, message):
        """發送TCP訊息"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((host, port))
            
            # 發送訊息長度
            msg_bytes = json.dumps(message).encode('utf-8')
            msg_len = struct.pack('>I', len(msg_bytes))
            sock.sendall(msg_len + msg_bytes)
            
            # 接收回應
            response_len = struct.unpack('>I', sock.recv(4))[0]
            response_data = b''
            while len(response_data) < response_len:
                packet = sock.recv(response_len - len(response_data))
                if not packet:
                    return None
                response_data += packet
            
            return json.loads(response_data.decode('utf-8'))
            
        finally:
            sock.close()
    
    @staticmethod
    def start_tcp_server(port, handler):
        """啟動TCP伺服器"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(('', port))
        server_sock.listen(5)
        
        logging.info(f"TCP server started on port {port}")
        
        while True:
            client_sock, addr = server_sock.accept()
            thread = threading.Thread(target=NetworkUtils._handle_client, 
                                    args=(client_sock, addr, handler))
            thread.daemon = True
            thread.start()
    
    @staticmethod
    def _handle_client(client_sock, addr, handler):
        """處理客戶端連接"""
        try:
            # 接收訊息長度
            msg_len = struct.unpack('>I', client_sock.recv(4))[0]
            
            # 接收訊息
            msg_data = b''
            while len(msg_data) < msg_len:
                packet = client_sock.recv(msg_len - len(msg_data))
                if not packet:
                    return
                msg_data += packet
            
            message = json.loads(msg_data.decode('utf-8'))
            
            # 處理訊息
            response = handler(message, addr[0])
            
            # 發送回應
            response_bytes = json.dumps(response).encode('utf-8')
            response_len = struct.pack('>I', len(response_bytes))
            client_sock.sendall(response_len + response_bytes)
            
        except Exception as e:
            logging.error(f"Error handling client {addr}: {e}")
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