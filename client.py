#!/usr/bin/env python3
"""
CSE Communication System - Client Component
客戶端應用程式，用於加密通訊
"""

import sys
import json
import threading
import time
import getpass
from datetime import datetime
from common_utils import *

class CSEClient:
    def __init__(self, client_id, server_host):
        self.client_id = client_id
        self.server_host = server_host
        self.logger = setup_logger(f'CSEClient_{client_id}', f'client_{client_id}.log')
        self.three_p_jwt = None
        self.is_authenticated = False
        self.heartbeat_thread = None
        self.message_check_thread = None
        self.new_messages = []
        self.message_lock = threading.Lock()
        self.groups = {}  # 儲存已加入的群組

        # 服務端口
        self.server_port = NetworkUtils.SERVICE_PORTS['server']
        self.idp_port = NetworkUtils.SERVICE_PORTS['idp']
        self.kacls_port = NetworkUtils.SERVICE_PORTS['kacls']
        
        self.logger.info(f"Client {client_id} initialized")
    
    def register(self, idp_host, password):
        """向IdP註冊"""
        request = {
            'type': 'register',
            'client_id': self.client_id,
            'password': password
        }
        
        response = NetworkUtils.send_tcp_message(idp_host, self.idp_port, request)
        
        if response.get('status') == 'success':
            self.three_p_jwt = response.get('3p_jwt')
            self.logger.info("Registration successful")
            return True
        else:
            self.logger.error(f"Registration failed: {response.get('message')}")
            return False
    
    def authenticate(self, idp_host, password):
        """向IdP認證"""
        request = {
            'type': 'authenticate',
            'client_id': self.client_id,
            'password': password
        }
        
        response = NetworkUtils.send_tcp_message(idp_host, self.idp_port, request)
        
        if response.get('status') == 'success':
            self.three_p_jwt = response.get('3p_jwt')
            self.is_authenticated = True
            self.logger.info("Authentication successful")
            
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
    
    def _register_with_server(self):
        """向Server註冊"""
        request = {
            'type': 'register_client',
            'client_id': self.client_id,
            '3p_jwt': self.three_p_jwt
        }
        
        response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
        
        if response.get('status') == 'success':
            self.logger.info("Registered with server")
        else:
            self.logger.error(f"Server registration failed: {response.get('message')}")
    
    def _start_heartbeat(self):
        """啟動心跳線程"""
        def heartbeat():
            while self.is_authenticated:
                request = {
                    'type': 'heartbeat',
                    'client_id': self.client_id
                }
                try:
                    NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
                except Exception as e:
                    self.logger.error(f"Heartbeat failed: {e}")
                time.sleep(60)  # 每分鐘發送一次心跳
        
        self.heartbeat_thread = threading.Thread(target=heartbeat)
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
    
    def get_online_clients(self):
        """獲取在線客戶端列表"""
        request = {
            'type': 'get_online_clients',
            'client_id': self.client_id
        }
        
        response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
        
        if response.get('status') == 'success':
            return response.get('online_clients', [])
        else:
            self.logger.error(f"Failed to get online clients: {response.get('message')}")
            return []
    
    def create_group(self, group_name, member_ids):
        """創建群組"""
        request = {
            'type': 'create_group',
            'client_id': self.client_id,
            'group_name': group_name,
            'members': member_ids
        }
        
        response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
        
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
    
    def _get_my_groups(self):
        """獲取已加入的群組"""
        request = {
            'type': 'get_my_groups',
            'client_id': self.client_id
        }
        
        response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
        
        if response.get('status') == 'success':
            self.groups = response.get('groups', {})
            self.logger.info(f"Retrieved {len(self.groups)} groups")
        else:
            self.logger.error(f"Failed to get groups: {response.get('message')}")
    
    def send_message(self, receiver_id, message, kacls_host, is_group=False):
        """發送加密訊息"""
        # 生成DEK
        dek = CryptoUtils.generate_aes_key()
        
        # 加密訊息
        encrypted_message = CryptoUtils.encrypt_aes_gcm(dek, message)
        
        # 向KACLS請求包裝DEK
        wrap_request = {
            'type': 'wrap_dek',
            '3p_jwt': self.three_p_jwt,
            'dek': base64.b64encode(dek).decode('utf-8'),
            'client_id': self.client_id
        }
        
        wrap_response = NetworkUtils.send_tcp_message(kacls_host, self.kacls_port, wrap_request)
        
        if wrap_response.get('status') != 'success':
            self.logger.error(f"Failed to wrap DEK: {wrap_response.get('message')}")
            return False
        
        w_dek = wrap_response.get('w_dek')
        
        # 發送加密訊息到Server
        send_request = {
            'type': 'send_group_message' if is_group else 'send_message',
            'sender_id': self.client_id,
            'receiver_id': receiver_id,  # 如果是群組，這裡是group_id
            'encrypted_data': encrypted_message,
            'w_dek': w_dek
        }
        
        send_response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, send_request)
        
        if send_response.get('status') == 'success':
            target_type = "group" if is_group else "user"
            self.logger.info(f"Message sent to {target_type} {receiver_id}")
            return True
        else:
            self.logger.error(f"Failed to send message: {send_response.get('message')}")
            return False
    
    def receive_message(self, message_id, b_jwt, kacls_host):
        """接收並解密訊息"""
        # 從Server獲取訊息
        get_request = {
            'type': 'get_message',
            'client_id': self.client_id,
            'message_id': message_id,
            'b_jwt': b_jwt
        }
        
        get_response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, get_request)
        
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
        
        unwrap_response = NetworkUtils.send_tcp_message(kacls_host, self.kacls_port, unwrap_request)
        
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
    
    def _start_message_checker(self):
        """啟動訊息檢查線程"""
        def check_messages():
            while self.is_authenticated:
                try:
                    request = {
                        'type': 'check_messages',
                        'client_id': self.client_id
                    }
                    
                    response = NetworkUtils.send_tcp_message(
                        self.server_host, 
                        self.server_port, 
                        request
                    )
                    
                    if response.get('status') == 'success':
                        new_messages = response.get('new_messages', [])
                        
                        if new_messages:
                            with self.message_lock:
                                self.new_messages.extend(new_messages)
                            
                            # 顯示新訊息通知
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
                                    response = NetworkUtils.send_tcp_message(self.server_host, self.server_port, request)
                                    
                                    if response.get('status') == 'success':
                                        group_info = response.get('group')
                                        self.groups[group_id]['members'] = group_info['members']
                                    
                                    print(f"\n🎉 You've been added to group '{msg_info['group_name']}' by {msg_info['invited_by']}")
                                    print(f"   Members: {', '.join(self.groups[group_id]['members'])}")
                                elif msg_info.get('group_name'):
                                    # 原有的群組訊息處理
                                    print(f"\n🔔 New group message in '{msg_info['group_name']}' from {msg_info['from']} (ID: {msg_info['message_id']})")
                                else:
                                    # 原有的個人訊息處理
                                    print(f"\n🔔 New message from {msg_info['from']} (ID: {msg_info['message_id']})")
                                print("Type '4' to read messages or continue with your selection.")
                except Exception as e:
                    self.logger.error(f"Message check failed: {e}")
                
                time.sleep(3)  # 每3秒檢查一次新訊息
        
        self.message_check_thread = threading.Thread(target=check_messages)
        self.message_check_thread.daemon = True
        self.message_check_thread.start()

    def read_pending_messages(self, kacls_host):
        """讀取所有待處理的訊息"""
        with self.message_lock:
            pending = self.new_messages.copy()
            self.new_messages.clear()
        
        if not pending:
            print("No new messages.")
            return
        
        print(f"\n📬 You have {len(pending)} new message(s):")
        
        for msg_info in pending:
            if msg_info.get('group_name'):
                print(f"\n--- Group message in '{msg_info['group_name']}' from {msg_info['from']} ---")
            else:
                print(f"\n--- Message from {msg_info['from']} ---")
            print(f"Time: {msg_info['timestamp']}")
            
            # 自動接收並解密訊息
            decrypted = self.receive_message(
                msg_info['message_id'], 
                msg_info['b_jwt'], 
                kacls_host
            )
            
            if decrypted:
                print(f"Message: {decrypted['message']}")
            else:
                print("Failed to decrypt message.")
            print("-" * 40)

def main():
    if len(sys.argv) < 3:
        print("Usage: python client.py <client_id> <server_host> [idp_host] [kacls_host]")
        sys.exit(1)
    
    client_id = sys.argv[1]
    server_host = sys.argv[2]
    idp_host = sys.argv[3] if len(sys.argv) > 3 else server_host
    kacls_host = sys.argv[4] if len(sys.argv) > 4 else server_host
    
    client = CSEClient(client_id, server_host)
    
    # 互動式命令行界面
    while True:
        if not client.is_authenticated:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ")
            
            if choice == '1':
                password = getpass.getpass("Enter password: ")
                if client.register(idp_host, password):
                    print("Registration successful! Please login.")
            elif choice == '2':
                password = getpass.getpass("Enter password: ")
                if client.authenticate(idp_host, password):
                    print("Login successful!")
            elif choice == '3':
                break
        else:
            print("\n1. List online clients")
            print("2. Send direct message")
            print("3. Send group message")
            print("4. Read messages")
            print("5. Create group")
            print("6. List my groups")
            print("7. Logout")
            choice = input("Choose an option: ").strip()

            if choice == '1':
                online_clients = client.get_online_clients()
                print(f"Online clients: {', '.join(online_clients)}")
            elif choice == '2':
                receiver = input("Enter receiver ID: ").strip()
                message = input("Enter message: ")
                if client.send_message(receiver, message, kacls_host):
                    print("Message sent successfully!")
                else:
                    print("Failed to send message.")
            elif choice == '3':
                # 列出可用的群組
                if not client.groups:
                    print("You are not in any groups. Create a group first.")
                else:
                    print("\nYour groups:")
                    for group_id, group_info in client.groups.items():
                        print(f"  {group_id}: {group_info['name']} (members: {', '.join(group_info['members'])})")
                    
                    group_id = input("Enter group ID: ").strip()
                    if group_id in client.groups:
                        message = input("Enter message: ")
                        if client.send_message(group_id, message, kacls_host, is_group=True):
                            print("Group message sent successfully!")
                        else:
                            print("Failed to send group message.")
                    else:
                        print("Invalid group ID.")
            elif choice == '4':
                client.read_pending_messages(kacls_host)
            elif choice == '5':
                group_name = input("Enter group name: ").strip()
                members_input = input("Enter member IDs (comma-separated, you are included by default): ").strip()
                
                if members_input:
                    member_ids = [m.strip() for m in members_input.split(',')]
                else:
                    member_ids = []
                
                # 確保自己在成員列表中
                if client.client_id not in member_ids:
                    member_ids.append(client.client_id)
                
                success, result = client.create_group(group_name, member_ids)
                if success:
                    print(f"Group '{group_name}' created successfully! Group ID: {result}")
                else:
                    print(f"Failed to create group: {result}")
            elif choice == '6':
                if not client.groups:
                    print("You are not in any groups.")
                else:
                    print("\nYour groups:")
                    for group_id, group_info in client.groups.items():
                        print(f"  ID: {group_id}")
                        print(f"  Name: {group_info['name']}")
                        print(f"  Members: {', '.join(group_info['members'])}")
                        print("-" * 30)
            elif choice == '7':
                client.is_authenticated = False
                print("Logged out.")

if __name__ == "__main__":
    main()