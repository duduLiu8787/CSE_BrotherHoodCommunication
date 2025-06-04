#!/usr/bin/env python3
"""
CSE Communication System - Client Backend Component
客戶端後端邏輯 - 處理加密、通訊、認證等核心功能
"""

import json
import threading
import time
import base64
from datetime import datetime
from common_utils import *

class CSEClient:
    def __init__(self, client_id):
        self.client_id = client_id
        self.logger = setup_logger(f'CSEClient_{client_id}', f'client_{client_id}.log')
        
        # 加密相關
        self.client_private_key, self.client_public_key = CryptoUtils.generate_rsa_keypair()
        
        # 核心屬性
        self.three_p_jwt = None
        self.is_authenticated = False
        self.services = {}
        self.groups = {}
        self.online_clients = []
        self.service_discovered = threading.Event()
        self.stop_discovery = False
        
        # 服務端口
        self.server_port = NetworkUtils.SERVICE_PORTS['server']
        self.idp_port = NetworkUtils.SERVICE_PORTS['idp']
        self.kacls_port = NetworkUtils.SERVICE_PORTS['kacls']
        
        # 回調函數（由GUI設定）
        self.on_message_received = None
        self.on_group_invite = None
        self.on_status_update = None
        
        self.logger.info(f"Client {client_id} initialized with encryption support")
    
    def set_callbacks(self, on_message=None, on_group_invite=None, on_status_update=None):
        """設定回調函數"""
        self.on_message_received = on_message
        self.on_group_invite = on_group_invite
        self.on_status_update = on_status_update
    
    def discover_services(self, passphrase, timeout=30):
        """通過廣播發現服務"""
        self.logger.info("Starting service discovery...")
        self.stop_discovery = False
        
        # 啟動監聽線程
        listen_thread = threading.Thread(
            target=self._listen_for_server_broadcast, 
            args=(passphrase,)
        )
        listen_thread.daemon = True
        listen_thread.start()
        
        # 等待服務發現完成
        if self.service_discovered.wait(timeout):
            self.logger.info("Service discovery completed successfully")
            self.stop_discovery = True
            listen_thread.join(timeout=2)
            return True
        else:
            self.logger.error("Service discovery timeout")
            self.stop_discovery = True
            return False
    
    def _listen_for_server_broadcast(self, passphrase):
        """監聽服務器廣播"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind(('', NetworkUtils.BROADCAST_PORT))
        
        while not self.stop_discovery:
            try:
                data, addr = sock.recvfrom(4096)
                broadcast_data = json.loads(data.decode('utf-8'))
                
                # 解密廣播訊息
                key = CryptoUtils.derive_key_from_passphrase(passphrase)
                try:
                    decrypted_msg = CryptoUtils.decrypt_aes_gcm(key, broadcast_data['encrypted'])
                    message = json.loads(decrypted_msg)
                    
                    if message.get('type') == 'service_announcement' and message.get('role') == 'server':
                        if self.service_discovered.is_set():
                            continue
                            
                        self.logger.info(f"Discovered server at {addr[0]}")
                        self._respond_to_server(addr[0], message, passphrase)
                except Exception:
                    pass
                    
            except socket.timeout:
                continue
            except Exception as e:
                if not self.stop_discovery:
                    self.logger.error(f"Error in broadcast listener: {e}")
        
        sock.close()
        self.logger.info("Stopped listening for server broadcasts")
    
    def _respond_to_server(self, server_addr, server_message, passphrase):
        """響應服務器廣播並獲取所有服務信息"""
        if self.service_discovered.is_set():
            return
            
        time.sleep(0.5)
        
        server_public_key = CryptoUtils.deserialize_public_key(server_message.get('public_key'))
        
        response = {
            'type': 'client_discovery',
            'client_id': self.client_id,
            'public_key': CryptoUtils.serialize_public_key(self.client_public_key)
        }
        
        try:
            result = NetworkUtils.send_tcp_message(
                server_addr,
                server_message.get('port'),
                response,
                encrypt_with_public_key=server_public_key,
                sign_with_private_key=self.client_private_key
            )
            
            if result and result.get('status') == 'success':
                services_info = result.get('services', {})
                
                self.services['server'] = {
                    'address': server_addr,
                    'public_key': server_public_key
                }
                
                for role, info in services_info.items():
                    self.services[role] = {
                        'address': info['address'],
                        'public_key': CryptoUtils.deserialize_public_key(info['public_key'])
                    }
                
                self.logger.info(f"Discovered services: {list(self.services.keys())}")
                
                if all(role in self.services for role in ['server', 'idp', 'kacls']):
                    self.service_discovered.set()
                else:
                    self.logger.warning("Not all services discovered")
            else:
                self.logger.error(f"Server response was not successful: {result}")
        except Exception as e:
            self.logger.error(f"Failed to respond to server: {e}")
    
    def get_service_address(self, role):
        """獲取服務地址"""
        if role in self.services:
            return self.services[role]['address']
        return None
    
    def register(self, password):
        """向IdP註冊"""
        idp_host = self.get_service_address('idp')
        if not idp_host:
            self.logger.error("IdP service not discovered")
            return False
            
        request = {
            'type': 'register',
            'client_id': self.client_id,
            'password': password,
            'client_public_key': CryptoUtils.serialize_public_key(self.client_public_key)
        }
        
        response = NetworkUtils.send_tcp_message(
            idp_host, 
            self.idp_port, 
            request,
            encrypt_with_public_key=self.services['idp']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if response.get('status') == 'success':
            self.three_p_jwt = response.get('3p_jwt')
            self.logger.info("Registration successful")
            return True
        else:
            self.logger.error(f"Registration failed: {response.get('message')}")
            return False
    
    def authenticate(self, password, progress_callback=None):
        """向IdP認證（含挑戰驗證）"""
        idp_host = self.get_service_address('idp')
        if not idp_host:
            self.logger.error("IdP service not discovered")
            return False
            
        # 第一步：發送密碼進行驗證
        request = {
            'type': 'authenticate',
            'client_id': self.client_id,
            'password': password
        }
        
        response = NetworkUtils.send_tcp_message(
            idp_host, 
            self.idp_port, 
            request,
            encrypt_with_public_key=self.services['idp']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        # 檢查是否收到挑戰
        if response.get('status') == 'challenge':
            self.logger.info("Received authentication challenge from IdP")
            
            if progress_callback:
                progress_callback("正在進行挑戰驗證...")
            
            # 取得挑戰
            challenge = response.get('challenge')
            if not challenge:
                self.logger.error("No challenge provided")
                return False
            
            # 使用私鑰簽名挑戰
            try:
                signed_challenge = CryptoUtils.sign_data(self.client_private_key, challenge)
            except Exception as e:
                self.logger.error(f"Failed to sign challenge: {e}")
                return False
            
            # 第二步：發送簽名的挑戰
            challenge_response = {
                'type': 'auth_challenge_response',
                'client_id': self.client_id,
                'signed_challenge': signed_challenge
            }
            
            response = NetworkUtils.send_tcp_message(
                idp_host,
                self.idp_port,
                challenge_response,
                encrypt_with_public_key=self.services['idp']['public_key'],
                sign_with_private_key=self.client_private_key
            )
        
        # 處理最終回應
        if response.get('status') == 'success':
            self.three_p_jwt = response.get('3p_jwt')
            self.is_authenticated = True
            self.logger.info("Authentication successful with challenge verification")
            
            # 向Server註冊
            self._register_with_server()
            
            # 獲取已加入的群組
            self._get_my_groups()
            
            # 啟動心跳線程
            self._start_heartbeat()
            
            # 啟動訊息檢查線程
            self._start_message_checker()
            
            return True
        else:
            self.logger.error(f"Authentication failed: {response.get('message')}")
            return False
    
    def logout(self):
        """登出"""
        self.is_authenticated = False
        self.three_p_jwt = None
        self.stop_all_threads = True
        self.logger.info("Logged out")
    
    def _register_with_server(self):
        """向Server註冊"""
        server_host = self.get_service_address('server')
        if not server_host:
            self.logger.error("Server service not discovered")
            return
            
        request = {
            'type': 'register_client',
            'client_id': self.client_id,
            '3p_jwt': self.three_p_jwt,
            'public_key': CryptoUtils.serialize_public_key(self.client_public_key)
        }
        
        response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if response.get('status') == 'success':
            self.logger.info("Registered with server")
        else:
            self.logger.error(f"Server registration failed: {response.get('message')}")
    
    def _start_heartbeat(self):
        """啟動心跳線程"""
        def heartbeat():
            server_host = self.get_service_address('server')
            while self.is_authenticated and server_host and not getattr(self, 'stop_all_threads', False):
                request = {
                    'type': 'heartbeat',
                    'client_id': self.client_id
                }
                try:
                    NetworkUtils.send_tcp_message(
                        server_host, 
                        self.server_port, 
                        request,
                        encrypt_with_public_key=self.services['server']['public_key'],
                        sign_with_private_key=self.client_private_key
                    )
                except Exception as e:
                    self.logger.error(f"Heartbeat failed: {e}")
                time.sleep(60)
        
        heartbeat_thread = threading.Thread(target=heartbeat)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
    
    def _start_message_checker(self):
        """啟動訊息檢查線程"""
        def check_messages():
            server_host = self.get_service_address('server')
            while self.is_authenticated and server_host and not getattr(self, 'stop_all_threads', False):
                try:
                    request = {
                        'type': 'check_messages',
                        'client_id': self.client_id
                    }
                    
                    response = NetworkUtils.send_tcp_message(
                        server_host, 
                        self.server_port, 
                        request,
                        encrypt_with_public_key=self.services['server']['public_key'],
                        sign_with_private_key=self.client_private_key
                    )
                    
                    if response.get('status') == 'success':
                        new_messages = response.get('new_messages', [])
                        
                        for msg_info in new_messages:
                            if msg_info.get('type') == 'group_invite':
                                # 處理群組邀請
                                group_id = msg_info['group_id']
                                
                                # 先加入基本資訊
                                self.groups[group_id] = {
                                    'name': msg_info['group_name'],
                                    'members': []
                                }
                                
                                # 獲取完整群組資訊
                                request = {
                                    'type': 'get_group_info',
                                    'client_id': self.client_id,
                                    'group_id': group_id
                                }
                                response = NetworkUtils.send_tcp_message(
                                    server_host, 
                                    self.server_port, 
                                    request,
                                    encrypt_with_public_key=self.services['server']['public_key'],
                                    sign_with_private_key=self.client_private_key
                                )
                                
                                if response.get('status') == 'success':
                                    group_info = response.get('group')
                                    self.groups[group_id]['members'] = group_info['members']
                                
                                # 通知GUI
                                if self.on_group_invite:
                                    self.on_group_invite(
                                        group_id,
                                        msg_info['group_name'],
                                        msg_info['invited_by']
                                    )
                            else:
                                # 自動讀取並解密訊息
                                threading.Thread(
                                    target=self._process_new_message,
                                    args=(msg_info,),
                                    daemon=True
                                ).start()
                            
                except Exception as e:
                    self.logger.error(f"Message check failed: {e}")
                
                time.sleep(3)  # 每3秒檢查一次新訊息
        
        message_check_thread = threading.Thread(target=check_messages)
        message_check_thread.daemon = True
        message_check_thread.start()
    
    def _process_new_message(self, msg_info):
        """處理新訊息"""
        try:
            server_host = self.get_service_address('server')
            if not server_host:
                return
            
            # 認領訊息
            claim_request = {
                'type': 'claim_message',
                'client_id': self.client_id,
                'message_id': msg_info['message_id']
            }
            
            response = NetworkUtils.send_tcp_message(
                server_host, 
                self.server_port, 
                claim_request,
                encrypt_with_public_key=self.services['server']['public_key'],
                sign_with_private_key=self.client_private_key
            )
            
            # 處理挑戰
            if response.get('status') == 'challenge':
                challenge = response.get('challenge')
                claim_request['challenge_response'] = challenge
                response = NetworkUtils.send_tcp_message(
                    server_host, 
                    self.server_port, 
                    claim_request,
                    encrypt_with_public_key=self.services['server']['public_key'],
                    sign_with_private_key=self.client_private_key
                )
            
            if response.get('status') == 'success':
                b_jwt = response.get('b_jwt')
                
                # 使用 B_JWT 接收並解密訊息
                decrypted = self.receive_message(msg_info['message_id'], b_jwt)
                
                if decrypted and self.on_message_received:
                    # 通知GUI收到新訊息
                    self.on_message_received(decrypted)
                    
        except Exception as e:
            self.logger.error(f"Process new message error: {e}")
    
    def get_online_clients(self):
        """獲取在線客戶端列表"""
        server_host = self.get_service_address('server')
        if not server_host:
            self.logger.error("Server service not discovered")
            return []
            
        request = {
            'type': 'get_online_clients',
            'client_id': self.client_id
        }
        
        response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if response.get('status') == 'success':
            return response.get('online_clients', [])
        else:
            self.logger.error(f"Failed to get online clients: {response.get('message')}")
            return []
    
    def create_group(self, group_name, member_ids):
        """創建群組"""
        server_host = self.get_service_address('server')
        if not server_host:
            self.logger.error("Server service not discovered")
            return False, "Server not available"
            
        request = {
            'type': 'create_group',
            'client_id': self.client_id,
            'group_name': group_name,
            'members': member_ids
        }
        
        response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if response.get('status') == 'success':
            group_id = response.get('group_id')
            self.groups[group_id] = {
                'name': group_name,
                'members': member_ids
            }
            self.logger.info(f"Group '{group_name}' created with ID: {group_id}")
            return True, group_id
        else:
            self.logger.error(f"Failed to create group: {response.get('message')}")
            return False, response.get('message')
    
    def get_my_groups(self):
        """獲取已加入的群組"""
        self._get_my_groups()
        return self.groups
    
    def _get_my_groups(self):
        """內部方法：獲取已加入的群組"""
        server_host = self.get_service_address('server')
        if not server_host:
            return
            
        request = {
            'type': 'get_my_groups',
            'client_id': self.client_id
        }
        
        response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if response.get('status') == 'success':
            self.groups = response.get('groups', {})
            self.logger.info(f"Retrieved {len(self.groups)} groups")
        else:
            self.logger.error(f"Failed to get groups: {response.get('message')}")
    
    def send_message(self, receiver_id, message, is_group=False):
        """發送加密訊息"""
        kacls_host = self.get_service_address('kacls')
        server_host = self.get_service_address('server')
        
        if not kacls_host or not server_host:
            self.logger.error("Required services not discovered")
            return False
            
        # 生成DEK
        dek = CryptoUtils.generate_aes_key()
        
        # 加密訊息
        encrypted_message = CryptoUtils.encrypt_aes_gcm(dek, message)
        
        # 向KACLS請求包裝DEK
        if is_group:
            group_members = self.groups.get(receiver_id, {}).get('members', [])
            wrap_request = {
                'type': 'wrap_dek',
                '3p_jwt': self.three_p_jwt,
                'dek': base64.b64encode(dek).decode('utf-8'),
                'client_id': self.client_id,
                'receivers': group_members,
                'is_group': True,
                'group_id': receiver_id
            }
        else:
            wrap_request = {
                'type': 'wrap_dek',
                '3p_jwt': self.three_p_jwt,
                'dek': base64.b64encode(dek).decode('utf-8'),
                'client_id': self.client_id,
                'receivers': [receiver_id]
            }
        
        wrap_response = NetworkUtils.send_tcp_message(
            kacls_host, 
            self.kacls_port, 
            wrap_request,
            encrypt_with_public_key=self.services['kacls']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if wrap_response.get('status') != 'success':
            self.logger.error(f"Failed to wrap DEK: {wrap_response.get('message')}")
            return False
        
        w_dek = wrap_response.get('w_dek')
        
        # 發送加密訊息到Server
        send_request = {
            'type': 'send_group_message' if is_group else 'send_message',
            'sender_id': self.client_id,
            'receiver_id': receiver_id,
            'encrypted_data': encrypted_message,
            'w_dek': w_dek
        }
        
        send_response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            send_request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if send_response.get('status') == 'success':
            target_type = "group" if is_group else "user"
            self.logger.info(f"Message sent to {target_type} {receiver_id}")
            return True
        else:
            self.logger.error(f"Failed to send message: {send_response.get('message')}")
            return False
    
    def receive_message(self, message_id, b_jwt):
        """接收並解密訊息"""
        server_host = self.get_service_address('server')
        kacls_host = self.get_service_address('kacls')
        
        if not server_host or not kacls_host:
            self.logger.error("Required services not discovered")
            return None
            
        # 從Server獲取訊息
        get_request = {
            'type': 'get_message',
            'client_id': self.client_id,
            'message_id': message_id,
            'b_jwt': b_jwt
        }
        
        get_response = NetworkUtils.send_tcp_message(
            server_host, 
            self.server_port, 
            get_request,
            encrypt_with_public_key=self.services['server']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if get_response.get('status') != 'success':
            self.logger.error(f"Failed to get message: {get_response.get('message')}")
            return None
        
        message_data = get_response.get('message')
        
        # 向KACLS請求解包DEK
        unwrap_request = {
            'type': 'unwrap_dek',
            '3p_jwt': self.three_p_jwt,
            'b_jwt': b_jwt,
            'w_dek': message_data['w_dek'],
            'client_id': self.client_id
        }
        
        unwrap_response = NetworkUtils.send_tcp_message(
            kacls_host, 
            self.kacls_port, 
            unwrap_request,
            encrypt_with_public_key=self.services['kacls']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
        if unwrap_response.get('status') != 'success':
            self.logger.error(f"Failed to unwrap DEK: {unwrap_response.get('message')}")
            return None
        
        dek = base64.b64decode(unwrap_response.get('dek'))
        
        # 解密訊息
        try:
            decrypted_message = CryptoUtils.decrypt_aes_gcm(dek, message_data['data'])
            self.logger.info(f"Message received from {message_data['from']}")
            return {
                'from': message_data['from'],
                'message': decrypted_message,
                'timestamp': message_data['timestamp'],
                'group_id': message_data.get('group_id'),
                'group_name': message_data.get('group_name')
            }
        except Exception as e:
            self.logger.error(f"Failed to decrypt message: {e}")
            return None