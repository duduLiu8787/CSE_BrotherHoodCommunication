#!/usr/bin/env python3
"""
CSE Communication System - Server Component
負責轉送加密內容、驗證權限、管理在線成員、管理群組 - 加密通訊版本
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
        self.online_clients = {}  # {client_id: {'address': addr, 'last_seen': timestamp, 'public_key': key}}
        self.messages = {}  # {message_id: {'from': sender, 'to': receiver, 'data': encrypted_data, 'w_dek': w_dek}}
        self.groups = {}  # {group_id: {'name': name, 'members': [client_ids], 'created_by': client_id}}
        self.client_lock = threading.Lock()
        self.message_lock = threading.Lock()
        self.group_lock = threading.Lock()
        self.is_broadcasting = True
        self.continue_broadcast_for_clients = True
        
        # Server 自己不需要註冊到 registry，但需要記錄需要的服務
        self.required_services = {'idp', 'kacls'}
        
        self.logger.info("Server initialized with encryption support")
    
    def _are_all_services_registered(self):
        """檢查是否所有必需的服務都已註冊"""
        with self.registry.lock:
            registered = set(self.registry.services.keys())
            return self.required_services.issubset(registered)
    
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
        self.logger.info("Waiting for all services to register...")
        while not self._are_all_services_registered():
            with self.registry.lock:
                registered = list(self.registry.services.keys())
            self.logger.debug(f"Currently registered services: {registered}")
            self.logger.debug(f"Required services: {list(self.required_services)}")
            time.sleep(5)
        
        self.is_broadcasting = False
        self.logger.info("All services registered, stopping service discovery broadcast")
        
        # 輸出最終註冊的服務
        with self.registry.lock:
            final_services = list(self.registry.services.keys())
        self.logger.info(f"Final registered services: {final_services}")
        
        # 但繼續為客戶端廣播
        client_broadcast_thread = threading.Thread(target=self._broadcast_for_clients)
        client_broadcast_thread.daemon = True
        client_broadcast_thread.start()
        
        # 保持主線程運行
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.continue_broadcast_for_clients = False
            pass
    
    def _broadcast_service(self):
        """廣播服務存在（用於服務發現）"""
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
    
    def _broadcast_for_clients(self):
        """為客戶端持續廣播"""
        self.logger.info("Starting client discovery broadcast")
        while self.continue_broadcast_for_clients:
            # 只有在所有服務都準備好後才廣播
            if self._are_all_services_registered():
                message = {
                    'type': 'service_announcement',
                    'role': 'server',
                    'public_key': CryptoUtils.serialize_public_key(self.public_key),
                    'port': NetworkUtils.SERVICE_PORTS['server']
                }
                NetworkUtils.send_broadcast(message, self.passphrase)
                self.logger.debug("Broadcasted for client discovery")
            time.sleep(5)
    
    def _listen_for_services(self):
        """監聽其他服務的響應"""
        def handle_broadcast(message, addr):
            if message.get('type') == 'service_response':
                role = message.get('role')
                if role in ['idp', 'kacls']:
                    # 不需要驗證明文密語，能解密就表示密語正確
                    public_key = CryptoUtils.deserialize_public_key(message.get('public_key'))
                    self.registry.register_service(role, addr, public_key)
                    self.logger.info(f"Registered {role} service from {addr} via broadcast")
        
        NetworkUtils.listen_broadcast(self.passphrase, handle_broadcast)
    
    def _start_tcp_service(self):
        """啟動TCP服務 - 加密版本"""
        NetworkUtils.start_tcp_server(
            NetworkUtils.SERVICE_PORTS['server'],
            self._handle_client_request,
            self.private_key,
            self.registry
        )
    
    def _handle_client_request(self, request, client_addr):
        """處理客戶端請求"""
        request_type = request.get('type')
        self.logger.debug(f"Handling request type: {request_type} from {client_addr}")
        
        try:
            if request_type == 'service_response':
                return self._handle_service_response(request, client_addr)
            elif request_type == 'client_discovery':
                return self._handle_client_discovery(request, client_addr)
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
            elif request_type == 'claim_message':
                return self._handle_claim_message(request, client_addr)
            elif request_type == 'heartbeat':
                return self._handle_heartbeat(request, client_addr)
            elif request_type == 'create_group':
                return self._handle_create_group(request, client_addr)
            elif request_type == 'get_my_groups':
                return self._handle_get_my_groups(request)
            elif request_type == 'get_group_info':
                return self._handle_get_group_info(request)
            else:
                return {'status': 'error', 'message': f'Unknown request type: {request_type}'}
        except Exception as e:
            self.logger.error(f"Error handling request type {request_type}: {e}")
            import traceback
            traceback.print_exc()
            return {'status': 'error', 'message': str(e)}
    
    def _handle_client_discovery(self, request, client_addr):
        """處理客戶端發現請求"""
        client_id = request.get('client_id')
        client_public_key = request.get('public_key')
        
        # 能夠解密請求就表示通關密語正確
        
        # 檢查所有服務是否都已註冊
        if not self._are_all_services_registered():
            self.logger.warning(f"Client {client_id} tried to connect before all services are ready")
            return {'status': 'error', 'message': 'Services not ready'}
        
        # 準備服務信息
        services_info = {}
        
        # 添加IdP信息
        idp_addr = self.registry.get_service('idp')
        if idp_addr:
            services_info['idp'] = {
                'address': idp_addr,
                'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('idp'))
            }
        
        # 添加KACLS信息
        kacls_addr = self.registry.get_service('kacls')
        if kacls_addr:
            services_info['kacls'] = {
                'address': kacls_addr,
                'public_key': CryptoUtils.serialize_public_key(self.registry.get_public_key('kacls'))
            }
        
        self.logger.info(f"Client {client_id} discovered services successfully")
        
        return {
            'status': 'success',
            'message': 'Services discovered',
            'services': services_info
        }
    
    def _handle_service_response(self, request, client_addr):
        """處理服務響應 - 加密版本"""
        role = request.get('role')
        self.logger.debug(f"Received service response from {client_addr}, role: {role}")
        
        if role in ['idp', 'kacls']:
            # 能夠解密就表示通關密語正確
            public_key = CryptoUtils.deserialize_public_key(request.get('public_key'))
            self.registry.register_service(role, client_addr, public_key)
            self.logger.info(f"Registered {role} service from {client_addr}")
            
            # 檢查並輸出當前註冊狀態
            with self.registry.lock:
                current_services = list(self.registry.services.keys())
            self.logger.info(f"Current registered services: {current_services}")
            self.logger.info(f"All services registered: {self._are_all_services_registered()}")
            
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
            
            if self._are_all_services_registered():
                self.logger.info("All services now registered, will notify others")
                self._notify_services_update()
                
            return {
                'status': 'success', 
                'message': f'{role} registered successfully',
                'other_services': other_services
            }
        else:
            self.logger.warning(f"Unknown service role: {role}")
            
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
        client_public_key = request.get('public_key')
        
        # 驗證客戶端是否已在IdP註冊
        idp_addr = self.registry.get_service('idp')
        if not idp_addr:
            return {'status': 'error', 'message': 'IdP service not available'}
        
        # 向IdP驗證客戶端 - 使用加密通道
        verify_request = {
            'type': 'verify_client',
            'client_id': client_id,
            '3p_jwt': request.get('3p_jwt')
        }
        
        idp_response = NetworkUtils.send_tcp_message(
            idp_addr,
            NetworkUtils.SERVICE_PORTS['idp'],
            verify_request,
            encrypt_with_public_key=self.registry.get_public_key('idp'),
            sign_with_private_key=self.private_key
        )
        
        if idp_response.get('status') == 'success':
            with self.client_lock:
                self.online_clients[client_id] = {
                    'address': client_addr,
                    'last_seen': datetime.utcnow().isoformat(),
                    'pending_messages': [],
                    'public_key': CryptoUtils.deserialize_public_key(client_public_key) if client_public_key else None
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
            
            # 生成單一群組訊息ID
            message_id = f"group_{group_id}_{sender_id}_{datetime.utcnow().timestamp()}"

            # 儲存單一訊息副本
            with self.message_lock:
                self.messages[message_id] = {
                    'from': sender_id,
                    'group_id': group_id,
                    'group_name': group_info['name'],
                    'data': encrypted_data,
                    'w_dek': w_dek,
                    'timestamp': datetime.utcnow().isoformat(),
                    'is_group': True,
                    'recipients': group_info['members']
                }

            # 通知所有群組成員（不包含發送者）
            for member_id in group_info['members']:
                if member_id == sender_id:
                    continue
                
                if member_id not in self.online_clients:
                    continue
                
                # 只通知，不生成 B_JWT
                with self.client_lock:
                    if 'pending_messages' not in self.online_clients[member_id]:
                        self.online_clients[member_id]['pending_messages'] = []
                    
                    self.online_clients[member_id]['pending_messages'].append({
                        'message_id': message_id,  # 使用相同的 message_id
                        'from': sender_id,
                        'group_id': group_id,
                        'group_name': group_info['name'],
                        'timestamp': datetime.utcnow().isoformat(),
                        'requires_authentication': True
                    })

            self.logger.info(f"Group message {message_id} stored for group {group_id}")
        
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
                'timestamp': datetime.utcnow().isoformat(),
                'requires_authentication': True
            })
        
        self.logger.info(f"Message {message_id} stored for {receiver_id}")
        
        return {
            'status': 'success',
            'message_id': message_id,
            'b_jwt': b_jwt
        }

    def _handle_claim_message(self, request, client_addr):
        """處理訊息認領請求（包含挑戰驗證）"""
        client_id = request.get('client_id')
        message_id = request.get('message_id')
        challenge_response = request.get('challenge_response')
        
        # 初始化挑戰字典
        if not hasattr(self, 'challenges'):
            self.challenges = {}
        
        # 步驟1：如果沒有挑戰響應，發送挑戰
        if not challenge_response:
            challenge = os.urandom(32)
            challenge_key = f"{client_id}_{message_id}"
            self.challenges[challenge_key] = base64.b64encode(challenge).decode('utf-8')
            
            return {
                'status': 'challenge',
                'challenge': self.challenges[challenge_key]
            }
        
        # 步驟2：驗證挑戰響應
        challenge_key = f"{client_id}_{message_id}"
        stored_challenge = self.challenges.get(challenge_key)
        if not stored_challenge or challenge_response != stored_challenge:
            return {'status': 'error', 'message': 'Challenge verification failed'}
        
        # 清除挑戰
        del self.challenges[challenge_key]
        
        # 步驟3：檢查訊息權限
        with self.message_lock:
            message = self.messages.get(message_id)
            if not message:
                return {'status': 'error', 'message': 'Message not found'}
            
            # 檢查接收權限
            if message.get('is_group'):
                if client_id not in message.get('recipients', []):
                    return {'status': 'error', 'message': 'Not authorized'}
            else:
                if message.get('to') != client_id:
                    return {'status': 'error', 'message': 'Not authorized'}
        
        # 步驟4：生成 B_JWT
        b_jwt = JWTUtils.create_b_jwt(
            client_id,
            message_id,
            ['read'],
            self.private_key
        )
        
        self.logger.info(f"Message {message_id} claimed by {client_id} after challenge")
        
        return {
            'status': 'success',
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
            
            # 權限檢查
            if message.get('is_group', False):
                # 群組訊息：確認 client_id 是該群組成員
                group_id = message.get('group_id')
                with self.group_lock:
                    if (group_id not in self.groups
                            or client_id not in self.groups[group_id]['members']):
                        return {'status': 'error', 'message': 'Access denied'}
            else:
                # 點對點訊息：確認收件人正確
                if message.get('to') != client_id:
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
                    update_request,
                    encrypt_with_public_key=self.registry.get_public_key('idp'),
                    sign_with_private_key=self.private_key
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
                    update_request,
                    encrypt_with_public_key=self.registry.get_public_key('kacls'),
                    sign_with_private_key=self.private_key
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