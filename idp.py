#!/usr/bin/env python3
"""
CSE Communication System - IdP (Identity Provider) Component
負責管理用戶身份、註冊和驗證 - 加密通訊版本
"""

import sys
import json
import threading
import time
from datetime import datetime
from common_utils import *

class CSEIdP:
    def __init__(self, passphrase):
        self.passphrase = passphrase
        self.logger = setup_logger('CSEIdP', 'idp.log')
        self.registry = ServiceRegistry()
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self.registered_clients = {}  # {client_id: {'password_salt': salt, 'password_hash': hash, 'public_key': key, 'registered_at': timestamp}}
        self.client_lock = threading.Lock()
        self.has_responded_to_server = False
        
        self.logger.info("IdP initialized with encryption support")
    
    def start(self):
        """啟動IdP服務"""
        # 啟動廣播監聽線程
        listen_thread = threading.Thread(target=self._listen_for_broadcasts)
        listen_thread.daemon = True
        listen_thread.start()
        
        # 啟動TCP服務
        self._start_tcp_service()
    
    def _listen_for_broadcasts(self):
        """監聽服務廣播"""
        def handle_broadcast(message, addr):
            if message.get('type') == 'service_announcement' and message.get('role') == 'server':
                # 響應Server的廣播
                self._respond_to_server(addr, message)
        
        NetworkUtils.listen_broadcast(self.passphrase, handle_broadcast)
    
    def _respond_to_server(self, server_addr, server_message):
        """響應Server的廣播 - 加密版本"""
        # 如果已經響應過，就不再響應
        if self.has_responded_to_server:
            return
        
        # 等待一下確保Server的TCP服務已啟動
        time.sleep(0.5)
        
        # 驗證並註冊Server
        server_public_key = CryptoUtils.deserialize_public_key(server_message.get('public_key'))
        self.registry.register_service('server', server_addr, server_public_key)
        
        # 發送加密響應
        response = {
            'type': 'service_response',
            'role': 'idp',
            'public_key': CryptoUtils.serialize_public_key(self.public_key)
        }
        
        # 使用Server的公鑰加密並簽名
        try:
            result = NetworkUtils.send_tcp_message(
                server_addr,
                server_message.get('port'),
                response,
                encrypt_with_public_key=server_public_key,
                sign_with_private_key=self.private_key
            )
            if result and result.get('status') == 'success':
                self.has_responded_to_server = True
                self.logger.info(f"Successfully responded to server at {server_addr}")
                
                # 註冊其他服務（如果Server回傳了）
                other_services = result.get('other_services', {})
                for service_role, service_info in other_services.items():
                    service_public_key = CryptoUtils.deserialize_public_key(service_info['public_key'])
                    self.registry.register_service(service_role, service_info['address'], service_public_key)
                    self.logger.info(f"Registered {service_role} service at {service_info['address']}")
                    self.logger.info(f"Current registry state: {list(self.registry.services.keys())}")
            else:
                self.logger.error(f"Server response was not successful: {result}")
        except Exception as e:
            self.logger.error(f"Failed to respond to server: {e}")
    
    def _start_tcp_service(self):
        """啟動TCP服務 - 加密版本"""
        NetworkUtils.start_tcp_server(
            NetworkUtils.SERVICE_PORTS['idp'],
            self._handle_request,
            self.private_key,
            self.registry
        )
    
    def _handle_request(self, request, client_addr):
        """處理請求"""
        request_type = request.get('type')
        
        if request_type == 'register':
            return self._handle_registration(request)
        elif request_type == 'authenticate':
            return self._handle_authentication(request)
        elif request_type == 'verify_client':
            return self._handle_verify_client(request)
        elif request_type == 'verify_jwt':
            return self._handle_verify_jwt(request)
        elif request_type == 'update_services':
            return self._handle_update_services(request)
        else:
            return {'status': 'error', 'message': 'Unknown request type'}
    
    def _handle_registration(self, request):
        """處理客戶端註冊 - 安全版本"""
        client_id = request.get('client_id')
        password = request.get('password')
        client_public_key = request.get('client_public_key')
        
        if not client_id or not password:
            return {'status': 'error', 'message': 'Missing client_id or password'}
        
        with self.client_lock:
            if client_id in self.registered_clients:
                return {'status': 'error', 'message': 'Client already registered'}
            
            # 安全地儲存密碼
            salt, password_hash = SecurePasswordHandler.hash_password(password)
            
            self.registered_clients[client_id] = {
                'password_salt': base64.b64encode(salt).decode('utf-8'),
                'password_hash': base64.b64encode(password_hash).decode('utf-8'),
                'public_key': client_public_key,
                'registered_at': datetime.utcnow().isoformat()
            }
        
        # 創建3P_JWT
        jwt_token = JWTUtils.create_3p_jwt(client_id, self.private_key)
        
        self.logger.info(f"Registered new client: {client_id}")
        
        return {
            'status': 'success',
            'message': 'Registration successful',
            '3p_jwt': jwt_token
        }
    
    def _handle_authentication(self, request):
        """處理客戶端認證 - 安全版本"""
        client_id = request.get('client_id')
        password = request.get('password')
        
        if not client_id or not password:
            return {'status': 'error', 'message': 'Missing client_id or password'}
        
        with self.client_lock:
            client_info = self.registered_clients.get(client_id)
            if not client_info:
                return {'status': 'error', 'message': 'Client not registered'}
            
            # 驗證密碼
            salt = base64.b64decode(client_info['password_salt'])
            stored_hash = base64.b64decode(client_info['password_hash'])
            
            if not SecurePasswordHandler.verify_password(password, salt, stored_hash):
                return {'status': 'error', 'message': 'Invalid credentials'}
        
        # 創建新的3P_JWT
        jwt_token = JWTUtils.create_3p_jwt(client_id, self.private_key)
        
        self.logger.info(f"Authenticated client: {client_id}")
        
        return {
            'status': 'success',
            'message': 'Authentication successful',
            '3p_jwt': jwt_token
        }
    
    def _handle_verify_client(self, request):
        """驗證客戶端（供Server使用）"""
        client_id = request.get('client_id')
        jwt_token = request.get('3p_jwt')
        
        # 驗證JWT
        payload = JWTUtils.verify_jwt(jwt_token, self.public_key)
        
        if not payload:
            return {'status': 'error', 'message': 'Invalid JWT'}
        
        if payload.get('user_id') != client_id or payload.get('type') != '3P_JWT':
            return {'status': 'error', 'message': 'JWT validation failed'}
        
        # 檢查客戶端是否註冊
        with self.client_lock:
            if client_id not in self.registered_clients:
                return {'status': 'error', 'message': 'Client not registered'}
        
        return {'status': 'success', 'message': 'Client verified'}
    
    def _handle_verify_jwt(self, request):
        """處理JWT驗證請求（供KACLS使用）"""
        token = request.get('token')
        token_type = request.get('token_type')
        
        if token_type == '3P_JWT':
            payload = JWTUtils.verify_jwt(token, self.public_key)
            if payload and payload.get('type') == '3P_JWT':
                # 檢查用戶是否仍然註冊
                with self.client_lock:
                    if payload.get('user_id') in self.registered_clients:
                        return {'status': 'success', 'valid': True, 'payload': payload}
        
        return {'status': 'success', 'valid': False}
    
    def _handle_update_services(self, request):
        """處理服務更新請求"""
        services = request.get('services', {})
        
        for service_role, service_info in services.items():
            service_public_key = CryptoUtils.deserialize_public_key(service_info['public_key'])
            self.registry.register_service(service_role, service_info['address'], service_public_key)
            self.logger.info(f"Updated {service_role} service at {service_info['address']}")
        
        return {'status': 'success', 'message': 'Services updated'}
    
def main():
    if len(sys.argv) != 2:
        print("Usage: python idp.py <passphrase>")
        sys.exit(1)
    
    passphrase = sys.argv[1]
    idp = CSEIdP(passphrase)
    
    try:
        idp.start()
    except KeyboardInterrupt:
        print("\nIdP shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()