#!/usr/bin/env python3
"""
CSE Communication System - Server Component
負責轉送加密內容、驗證權限、管理在線成員、管理群組
"""

import sys
import json
import threading
import time
from datetime import datetime
from common_utils import *

class CSEServer:
    def __init__(self, passphrase):
        self.passphrase = passphrase
        self.logger = setup_logger('CSEServer', 'server.log')
        self.registry = ServiceRegistry()
        self.private_key, self.public_key = CryptoUtils.generate_rsa_keypair()
        self.online_clients = {}  # {client_id: {'address': addr, 'last_seen': timestamp}}
        self.messages = {}  # {message_id: {'from': sender, 'to': receiver, 'data': encrypted_data, 'w_dek': w_dek}}
        self.groups = {}  # {group_id: {'name': name, 'members': [client_ids], 'created_by': client_id}}
        self.client_lock = threading.Lock()
        self.message_lock = threading.Lock()
        self.group_lock = threading.Lock()
        self.is_broadcasting = True
        
        self.logger.info("Server initialized")
    
    def start(self):
        """啟動服務器"""
        # 先啟動TCP服務
        tcp_thread = threading.Thread(target=self._start_tcp_service)
        tcp_thread.daemon = True
        tcp_thread.start()
        
        # 等待TCP服務啟動
        time.sleep(1)
        
        # 啟動廣播線程
        broadcast_thread = threading.Thread(target=self._broadcast_service)
        broadcast_thread.daemon = True
        broadcast_thread.start()
        
        # 啟動廣播監聽線程
        listen_thread = threading.Thread(target=self._listen_for_services)
        listen_thread.daemon = True
        listen_thread.start()
        
        # 等待所有服務註冊完成
        while not self.registry.is_complete():
            time.sleep(1)
        
        self.is_broadcasting = False
        self.logger.info("All services registered, stopping broadcast")
        
        # 保持主線程運行
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    
    def _broadcast_service(self):
        """廣播服務存在"""
        while self.is_broadcasting:
            message = {
                'type': 'service_announcement',
                'role': 'server',
                'public_key': CryptoUtils.serialize_public_key(self.public_key),
                'port': NetworkUtils.SERVICE_PORTS['server']
            }
            NetworkUtils.send_broadcast(message, self.passphrase)
            self.logger.debug("Broadcasted service announcement")
            time.sleep(5)
    
    def _listen_for_services(self):
        """監聽其他服務的響應"""
        def handle_broadcast(message, addr):
            if message.get('type') == 'service_response':
                role = message.get('role')
                if role in ['idp', 'kacls']:
                    # 驗證通關密語
                    if message.get('passphrase') == self.passphrase:
                        public_key = CryptoUtils.deserialize_public_key(message.get('public_key'))
                        self.registry.register_service(role, addr, public_key)
                        self.logger.info(f"Registered {role} service from {addr}")
        
        NetworkUtils.listen_broadcast(self.passphrase, handle_broadcast)
    
    def _start_tcp_service(self):
        """啟動TCP服務"""
        NetworkUtils.start_tcp_server(
            NetworkUtils.SERVICE_PORTS['server'],
            self._handle_client_request
        )
    
    def _handle_client_request(self, request, client_addr):
        """處理客戶端請求"""
        request_type = request.get('type')
        
        if request_type == 'service_response':
            return self._handle_service_response(request, client_addr)
        elif request_type == 'register_client':
            return self._handle_client_registration(request, client_addr)
        elif request_type == 'send_message':
            return self._handle_send_message(request, client_addr)
        elif request_type == 'send_group_message':
            return self._handle_send_group_message(request, client_addr)
        elif request_type == 'get_message':
            return self._handle_get_message(request, client_addr)
        elif request_type == 'get_online_clients':
            return self._handle_get_online_clients(request)
        elif request_type == 'check_messages':
            return self._handle_check_messages(request)
        elif request_type == 'verify_jwt':
            return self._handle_verify_jwt(request)
        elif request_type == 'heartbeat':
            return self._handle_heartbeat(request, client_addr)
        elif request_type == 'create_group':
            return self._handle_create_group(request, client_addr)
        elif request_type == 'get_my_groups':
            return self._handle_get_my_groups(request)
        elif request_type == 'get_group_info':
            return self._handle_get_group_info(request)
        else:
            return {'status': 'error', 'message': 'Unknown request type'}
    
    def _handle_service_response(self, request, client_addr):
        """處理服務響應"""
        role = request.get('role')
        if role in ['idp', 'kacls']:
            # 驗證通關密語
            if request.get('passphrase') == self.passphrase:
                public_key = CryptoUtils.deserialize_public_key(request.get('public_key'))
                self.registry.register_service(role, client_addr, public_key)
                self.logger.info(f"Registered {role} service from {client_addr}")
                
                # 回傳其他服務的資訊
                other_services = {}
                if role == 'idp' and self.registry.get_service('kacls'):
                    other_services['kacls'] = {
                        'address': self.registry.get_service('kacls'),
                        'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('kacls'))
                    }
                elif role == 'kacls' and self.registry.get_service('idp'):
                    other_services['idp'] = {
                        'address': self.registry.get_service('idp'),
                        'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('idp'))
                    }
                if self.registry.is_complete():
                    self._notify_services_update()
                return {
                    'status': 'success', 
                    'message': f'{role} registered successfully',
                    'other_services': other_services
                }
        return {'status': 'error', 'message': 'Invalid service response'}
    
    def _handle_check_messages(self, request):
        """檢查是否有新訊息"""
        client_id = request.get('client_id')
    
        with self.client_lock:
            if client_id not in self.online_clients:
                return {'status': 'error', 'message': 'Client not registered'}
        
            pending_messages = self.online_clients[client_id].get('pending_messages', [])
        
            # 清空待處理訊息列表
            self.online_clients[client_id]['pending_messages'] = []
    
        return {
            'status': 'success',
            'new_messages': pending_messages
        }

    def _handle_client_registration(self, request, client_addr):
        """處理客戶端註冊"""
        client_id = request.get('client_id')
        
        # 驗證客戶端是否已在IdP註冊
        idp_addr = self.registry.get_service('idp')
        if not idp_addr:
            return {'status': 'error', 'message': 'IdP service not available'}
        
        # 向IdP驗證客戶端
        verify_request = {
            'type': 'verify_client',
            'client_id': client_id,
            '3p_jwt': request.get('3p_jwt')
        }
        
        idp_response = NetworkUtils.send_tcp_message(
            idp_addr,
            NetworkUtils.SERVICE_PORTS['idp'],
            verify_request
        )
        
        if idp_response.get('status') == 'success':
            with self.client_lock:
                self.online_clients[client_id] = {
                    'address': client_addr,
                    'last_seen': datetime.utcnow().isoformat(),
                    'pending_messages': []
                }
            self.logger.info(f"Client {client_id} registered from {client_addr}")
            return {'status': 'success', 'message': 'Client registered successfully'}
        else:
            return {'status': 'error', 'message': 'Client verification failed'}
    
    def _handle_create_group(self, request, client_addr):
        """處理創建群組請求"""
        client_id = request.get('client_id')
        group_name = request.get('group_name')
        members = request.get('members', [])
        
        # 驗證客戶端身份
        if client_id not in self.online_clients:
            return {'status': 'error', 'message': 'Client not registered'}
        
        # 確保創建者在成員列表中
        if client_id not in members:
            members.append(client_id)
        
        # 生成群組ID
        group_id = f"group_{datetime.utcnow().timestamp()}_{client_id}"
        
        # 創建群組
        with self.group_lock:
            self.groups[group_id] = {
                'name': group_name,
                'members': members,
                'created_by': client_id,
                'created_at': datetime.utcnow().isoformat()
            }
        
        self.logger.info(f"Group '{group_name}' (ID: {group_id}) created by {client_id}")
        # 通知所有成員（除了創建者）
        for member_id in members:
            if member_id != client_id and member_id in self.online_clients:
                notification_id = f"group_invite_{group_id}_{member_id}_{datetime.utcnow().timestamp()}"
                
                with self.client_lock:
                    self.online_clients[member_id]['pending_messages'].append({
                        'message_id': notification_id,
                        'type': 'group_invite',
                        'group_id': group_id,
                        'group_name': group_name,
                        'invited_by': client_id,
                        'timestamp': datetime.utcnow().isoformat()
                    })

        return {
            'status': 'success',
            'group_id': group_id,
            'message': 'Group created successfully'
        }
    
    def _handle_get_my_groups(self, request):
        """處理獲取我的群組請求"""
        client_id = request.get('client_id')
        
        # 獲取客戶端所在的所有群組
        my_groups = {}
        with self.group_lock:
            for group_id, group_info in self.groups.items():
                if client_id in group_info['members']:
                    my_groups[group_id] = {
                        'name': group_info['name'],
                        'members': group_info['members']
                    }
        
        return {
            'status': 'success',
            'groups': my_groups
        }
    
    def _handle_get_group_info(self, request):
        """獲取單一群組的詳細資訊"""
        group_id = request.get('group_id')
        client_id = request.get('client_id')
        
        with self.group_lock:
            if group_id in self.groups and client_id in self.groups[group_id]['members']:
                return {
                    'status': 'success',
                    'group': self.groups[group_id]
                }
        
        return {'status': 'error', 'message': 'Group not found or access denied'}

    def _handle_send_group_message(self, request, client_addr):
        """處理發送群組訊息請求"""
        sender_id = request.get('sender_id')
        group_id = request.get('receiver_id')  # 這裡receiver_id實際上是group_id
        encrypted_data = request.get('encrypted_data')
        w_dek = request.get('w_dek')
        
        # 驗證發送者身份
        if sender_id not in self.online_clients:
            return {'status': 'error', 'message': 'Sender not registered'}
        
        # 檢查群組是否存在
        with self.group_lock:
            if group_id not in self.groups:
                return {'status': 'error', 'message': 'Group not found'}
            
            group_info = self.groups[group_id]
            
            # 檢查發送者是否是群組成員
            if sender_id not in group_info['members']:
                return {'status': 'error', 'message': 'Sender not a member of this group'}
            
            # 為每個群組成員創建訊息
            for member_id in group_info['members']:
                if member_id == sender_id:  # 跳過發送者自己
                    continue
                
                if member_id not in self.online_clients:  # 跳過離線成員
                    continue
                
                # 生成訊息ID
                message_id = f"group_{group_id}_{sender_id}_{member_id}_{datetime.utcnow().timestamp()}"
                
                # 創建B_JWT
                b_jwt = JWTUtils.create_b_jwt(
                    member_id,
                    message_id,
                    ['read'],
                    self.private_key
                )
                
                # 儲存訊息
                with self.message_lock:
                    self.messages[message_id] = {
                        'from': sender_id,
                        'to': member_id,
                        'group_id': group_id,
                        'group_name': group_info['name'],
                        'data': encrypted_data,
                        'w_dek': w_dek,
                        'timestamp': datetime.utcnow().isoformat(),
                        'read': False
                    }
                
                # 將新訊息加入接收者的待處理列表
                with self.client_lock:
                    if 'pending_messages' not in self.online_clients[member_id]:
                        self.online_clients[member_id]['pending_messages'] = []
                    
                    self.online_clients[member_id]['pending_messages'].append({
                        'message_id': message_id,
                        'from': sender_id,
                        'group_id': group_id,
                        'group_name': group_info['name'],
                        'b_jwt': b_jwt,
                        'timestamp': datetime.utcnow().isoformat()
                    })
                
                self.logger.info(f"Group message {message_id} stored for {member_id}")
        
        return {
            'status': 'success',
            'message': 'Group message sent successfully'
        }
    
    def _handle_send_message(self, request, client_addr):
        """處理發送訊息請求"""
        sender_id = request.get('sender_id')
        receiver_id = request.get('receiver_id')
        encrypted_data = request.get('encrypted_data')
        w_dek = request.get('w_dek')
        
        # 驗證發送者身份
        if sender_id not in self.online_clients:
            return {'status': 'error', 'message': 'Sender not registered'}
        
        # 檢查接收者是否在線
        if receiver_id not in self.online_clients:
            return {'status': 'error', 'message': 'Receiver not online'}
        
        # 生成訊息ID
        message_id = f"{sender_id}_{receiver_id}_{datetime.utcnow().timestamp()}"
        
        # 先創建B_JWT
        b_jwt = JWTUtils.create_b_jwt(
            receiver_id,
            message_id,
            ['read'],
            self.private_key
        )
        
        # 儲存訊息
        with self.message_lock:
            self.messages[message_id] = {
                'from': sender_id,
                'to': receiver_id,
                'data': encrypted_data,
                'w_dek': w_dek,
                'timestamp': datetime.utcnow().isoformat(),
                'read': False
            }
        
        # 將新訊息加入接收者的待處理列表
        with self.client_lock:
            if 'pending_messages' not in self.online_clients[receiver_id]:
                self.online_clients[receiver_id]['pending_messages'] = []
            
            self.online_clients[receiver_id]['pending_messages'].append({
                'message_id': message_id,
                'from': sender_id,
                'b_jwt': b_jwt,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        self.logger.info(f"Message {message_id} stored for {receiver_id}")
        
        return {
            'status': 'success',
            'message_id': message_id,
            'b_jwt': b_jwt
        }
    
    def _handle_get_message(self, request, client_addr):
        """處理獲取訊息請求"""
        client_id = request.get('client_id')
        message_id = request.get('message_id')
        b_jwt = request.get('b_jwt')
        
        # 驗證B_JWT
        payload = JWTUtils.verify_jwt(b_jwt, self.public_key)
        if not payload or payload.get('user_id') != client_id:
            return {'status': 'error', 'message': 'Invalid B_JWT'}
        
        # 檢查權限
        if 'read' not in payload.get('permissions', []):
            return {'status': 'error', 'message': 'No read permission'}
        
        # 獲取訊息
        with self.message_lock:
            message = self.messages.get(message_id)
            if not message:
                return {'status': 'error', 'message': 'Message not found'}
            
            if message['to'] != client_id:
                return {'status': 'error', 'message': 'Access denied'}
        
        response_data = {
            'status': 'success',
            'message': {
                'from': message['from'],
                'data': message['data'],
                'w_dek': message['w_dek'],
                'timestamp': message['timestamp']
            }
        }
        
        # 如果是群組訊息，加入群組資訊
        if 'group_id' in message:
            response_data['message']['group_id'] = message['group_id']
            response_data['message']['group_name'] = message['group_name']
        
        return response_data
    
    def _handle_get_online_clients(self, request):
        """處理獲取在線客戶端列表請求"""
        with self.client_lock:
            # 清理超時的客戶端
            current_time = datetime.utcnow()
            timeout_clients = []
            for client_id, info in self.online_clients.items():
                last_seen = datetime.fromisoformat(info['last_seen'])
                if (current_time - last_seen).seconds > 300:  # 5分鐘超時
                    timeout_clients.append(client_id)
            
            for client_id in timeout_clients:
                del self.online_clients[client_id]
                self.logger.info(f"Client {client_id} timed out")
            
            # 返回在線客戶端列表
            online_list = list(self.online_clients.keys())
        
        return {
            'status': 'success',
            'online_clients': online_list
        }
    
    def _handle_verify_jwt(self, request):
        """處理JWT驗證請求（供其他服務使用）"""
        token = request.get('token')
        token_type = request.get('token_type')
        
        if token_type == 'B_JWT':
            payload = JWTUtils.verify_jwt(token, self.public_key)
            if payload and payload.get('type') == 'B_JWT':
                return {'status': 'success', 'valid': True, 'payload': payload}
        
        return {'status': 'success', 'valid': False}
    
    def _handle_heartbeat(self, request, client_addr):
        """處理心跳包"""
        client_id = request.get('client_id')
        
        with self.client_lock:
            if client_id in self.online_clients:
                self.online_clients[client_id]['last_seen'] = datetime.utcnow().isoformat()
                return {'status': 'success'}
        
        return {'status': 'error', 'message': 'Client not registered'}
    
    def _notify_services_update(self):
        """通知所有服務更新其他服務的資訊"""
        self.logger.info("Notifying all services about complete registry")
        
        idp_addr = self.registry.get_service('idp')
        kacls_addr = self.registry.get_service('kacls')
        
        # 通知 IdP 關於 KACLS
        if idp_addr and kacls_addr:
            update_request = {
                'type': 'update_services',
                'services': {
                    'kacls': {
                        'address': kacls_addr,
                        'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('kacls'))
                    }
                }
            }
            
            try:
                NetworkUtils.send_tcp_message(
                    idp_addr,
                    NetworkUtils.SERVICE_PORTS['idp'],
                    update_request
                )
                self.logger.info("Notified IdP about KACLS service")
            except Exception as e:
                self.logger.error(f"Failed to notify IdP: {e}")
        
        # 通知 KACLS 關於 IdP
        if kacls_addr and idp_addr:
            update_request = {
                'type': 'update_services',
                'services': {
                    'idp': {
                        'address': idp_addr,
                        'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('idp'))
                    }
                }
            }
            
            try:
                NetworkUtils.send_tcp_message(
                    kacls_addr,
                    NetworkUtils.SERVICE_PORTS['kacls'],
                    update_request
                )
                self.logger.info("Notified KACLS about IdP service")
            except Exception as e:
                self.logger.error(f"Failed to notify KACLS: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python server.py <passphrase>")
        sys.exit(1)
    
    passphrase = sys.argv[1]
    server = CSEServer(passphrase)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()