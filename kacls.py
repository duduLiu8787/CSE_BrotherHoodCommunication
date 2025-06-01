#!/usr/bin/env python3
"""
CSE Communication System - KACLS (Key Access Control Lockdown Service) Component
負責管理KEK和DEK的加密解密
"""

import sys
import json
import threading
import time
from datetime import datetime
from common_utils import *

class CSEKACLS:
    def __init__(self, passphrase):
        self.passphrase = passphrase
        self.logger = setup_logger('CSEKACLS', 'kacls.log')
        self.registry = ServiceRegistry()
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        
        # 生成系統KEK (Key Encryption Key)
        self.kek = CryptoUtils.generate_aes_key()
        self.logger.info("Generated system KEK")
        
        # 用於記錄操作
        self.operation_log = []
        self.log_lock = threading.Lock()
        self.has_responded_to_server = False  # 新增標記
        
        self.logger.info("KACLS initialized")
    
    def start(self):
        """啟動KACLS服務"""
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
        """響應Server的廣播"""
        # 如果已經響應過，就不再響應
        if self.has_responded_to_server:
            return
        
        # 等待一下確保Server的TCP服務已啟動
        time.sleep(0.5)
        
        # 驗證並註冊Server
        server_public_key = CryptoUtils.deserialize_public_key(server_message.get('public_key'))
        self.registry.register_service('server', server_addr, server_public_key)
        
        # 發送響應
        response = {
            'type': 'service_response',
            'role': 'kacls',
            'passphrase': self.passphrase,  # 明文通關密語驗證
            'public_key': CryptoUtils.serialize_public_key(self.public_key)
        }
        
        # 直接發送TCP響應給Server
        try:
            result = NetworkUtils.send_tcp_message(
                server_addr,
                server_message.get('port'),
                response
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
            else:
                self.logger.error(f"Server response was not successful: {result}")
        except Exception as e:
            self.logger.error(f"Failed to respond to server: {e}")
    
    def _start_tcp_service(self):
        """啟動TCP服務"""
        NetworkUtils.start_tcp_server(
            NetworkUtils.SERVICE_PORTS['kacls'],
            self._handle_request
        )
    
    def _handle_request(self, request, client_addr):
        """處理請求"""
        request_type = request.get('type')
        
        if request_type == 'wrap_dek':
            return self._handle_wrap_dek(request)
        elif request_type == 'unwrap_dek':
            return self._handle_unwrap_dek(request)
        elif request_type == 'update_services':
            return self._handle_update_services(request)
        else:
            return {'status': 'error', 'message': 'Unknown request type'}
    
    def _verify_tokens(self, three_p_jwt, b_jwt=None):
        """驗證JWT tokens"""
        # 驗證3P_JWT
        idp_addr = self.registry.get_service('idp')
        if not idp_addr:
            return False, "IdP service not available"
        
        verify_3p_request = {
            'type': 'verify_jwt',
            'token': three_p_jwt,
            'token_type': '3P_JWT'
        }
        
        idp_response = NetworkUtils.send_tcp_message(
            idp_addr,
            NetworkUtils.SERVICE_PORTS['idp'],
            verify_3p_request
        )
        
        if not idp_response.get('valid'):
            return False, "Invalid 3P_JWT"
        
        # 如果提供了B_JWT，也要驗證
        if b_jwt:
            server_addr = self.registry.get_service('server')
            if not server_addr:
                return False, "Server service not available"
            
            verify_b_request = {
                'type': 'verify_jwt',
                'token': b_jwt,
                'token_type': 'B_JWT'
            }
            
            server_response = NetworkUtils.send_tcp_message(
                server_addr,
                NetworkUtils.SERVICE_PORTS['server'],
                verify_b_request
            )
            
            if not server_response.get('valid'):
                return False, "Invalid B_JWT"
        
        return True, "Tokens verified"
    
    def _handle_wrap_dek(self, request):
        """處理DEK加密請求"""
        three_p_jwt = request.get('3p_jwt')
        dek_base64 = request.get('dek')
        client_id = request.get('client_id')
        receivers = request.get('receivers', [])
        is_group = request.get('is_group', False)
        group_id = request.get('group_id')
        
        # 驗證3P_JWT
        valid, message = self._verify_tokens(three_p_jwt)
        if not valid:
            return {'status': 'error', 'message': message}
        
        try:
            # 解碼DEK
            dek = base64.b64decode(dek_base64)
            
            # 創建綁定資訊
            binding_info = {
                'sender_id': client_id,
                'authorized_receivers': receivers,
                'is_group': is_group,
                'group_id': group_id if is_group else None,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # 將綁定資訊與DEK一起加密
            combined_data = {
                'dek': base64.b64encode(dek).decode('utf-8'),
                'binding': binding_info
            }
            
            # 使用KEK加密
            w_dek_data = CryptoUtils.encrypt_aes_gcm(
                self.kek,
                json.dumps(combined_data).encode('utf-8'),
            )
            
            # 記錄操作
            with self.log_lock:
                self.operation_log.append({
                    'operation': 'wrap_dek',
                    'client_id': client_id,
                    'receivers_count': len(receivers),
                    'is_group': is_group,
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            self.logger.info(f"Wrapped DEK for {len(receivers)} receivers")
            
            return {
                'status': 'success',
                'w_dek': w_dek_data
            }
            
        except Exception as e:
            self.logger.error(f"Error wrapping DEK: {e}")
            return {'status': 'error', 'message': 'Failed to wrap DEK'}
    
    def _handle_unwrap_dek(self, request):
        """處理DEK解密請求"""
        three_p_jwt = request.get('3p_jwt')
        b_jwt = request.get('b_jwt')
        w_dek_data = request.get('w_dek')
        client_id = request.get('client_id')
        
        # 驗證兩個JWT
        valid, message = self._verify_tokens(three_p_jwt, b_jwt)
        if not valid:
            return {'status': 'error', 'message': message}
        
        try:
            # 解析JWT以獲取user_id
            b_jwt_payload = JWTUtils.verify_jwt(b_jwt, self.registry.get_public_key('server'))
            
            # 使用KEK解密獲取DEK和綁定資訊
            decrypted_data = CryptoUtils.decrypt_aes_gcm(
                self.kek,
                w_dek_data,
                decode_text=True
            )
            
            combined_data = json.loads(decrypted_data)
            binding_info = combined_data.get('binding', {})
            
            # 驗證客戶端是否在授權接收者列表中
            authorized_receivers = binding_info.get('authorized_receivers', [])
            if client_id not in authorized_receivers:
                self.logger.warning(f"Client {client_id} not in authorized receivers list")
                return {'status': 'error', 'message': 'Access denied - not authorized for this DEK'}
            
            # 驗證B_JWT的user_id也匹配
            if b_jwt_payload.get('user_id') != client_id:
                return {'status': 'error', 'message': 'B_JWT user mismatch'}
            
            dek = base64.b64decode(combined_data['dek'])
            
            # 記錄操作
            with self.log_lock:
                self.operation_log.append({
                    'operation': 'unwrap_dek',
                    'client_id': client_id,
                    'is_group': binding_info.get('is_group', False),
                    'timestamp': datetime.utcnow().isoformat()
                })
            
            self.logger.info(f"Unwrapped DEK for client {client_id}")
            
            return {
                'status': 'success',
                'dek': base64.b64encode(dek).decode('utf-8')
            }
            
        except Exception as e:
            self.logger.error(f"Error unwrapping DEK: {e}")
            return {'status': 'error', 'message': 'Failed to unwrap DEK'}
        
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
        print("Usage: python kacls.py <passphrase>")
        sys.exit(1)
    
    passphrase = sys.argv[1]
    kacls = CSEKACLS(passphrase)
    
    try:
        kacls.start()
    except KeyboardInterrupt:
        print("\nKACLS shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()