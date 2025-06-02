#!/usr/bin/env python3
"""
CSE Communication System - GUI Client Component
圖形化客戶端應用程式 - 加密通訊版本
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import sys
import json
import time
import base64
from datetime import datetime
from common_utils import *

class CSEClientGUI:
    def __init__(self, client_id):
        self.client_id = client_id
        self.logger = setup_logger(f'CSEClientGUI_{client_id}', f'client_gui_{client_id}.log')
        
        # 加密相關
        self.client_private_key, self.client_public_key = CryptoUtils.generate_rsa_keypair()
        
        # 核心屬性
        self.three_p_jwt = None
        self.is_authenticated = False
        self.services = {}
        self.groups = {}
        self.online_clients = []
        self.message_queue = queue.Queue()
        self.service_discovered = threading.Event()
        self.stop_discovery = False
        self.new_messages = []
        self.message_lock = threading.Lock()
        
        # 聊天記錄儲存
        self.chat_history = {}  # {user_id: [messages]}
        self.group_chat_history = {}  # {group_id: [messages]}
        
        # 服務端口
        self.server_port = NetworkUtils.SERVICE_PORTS['server']
        self.idp_port = NetworkUtils.SERVICE_PORTS['idp']
        self.kacls_port = NetworkUtils.SERVICE_PORTS['kacls']
        
        # 建立主視窗
        self.root = tk.Tk()
        self.root.title(f"CSE Client - {client_id}")
        self.root.geometry("900x700")
        
        # 設定樣式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 初始化 UI
        self.setup_ui()
        
        # 啟動訊息處理線程
        self.root.after(100, self.process_message_queue)
        
        self.logger.info(f"Client GUI {client_id} initialized with encryption support")
    
    def setup_ui(self):
        """設定使用者介面"""
        # 創建筆記本（分頁）
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 連線分頁
        self.connection_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.connection_frame, text="連線")
        self.setup_connection_tab()
        
        # 聊天分頁
        self.chat_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.chat_frame, text="聊天", state='disabled')
        self.setup_chat_tab()
        
        # 群組分頁
        self.group_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.group_frame, text="群組", state='disabled')
        self.setup_group_tab()
        
        # 狀態列
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar()
        self.status_var.set("未連線")
        self.status_bar = ttk.Label(self.status_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # 新訊息指示器
        self.new_msg_indicator = ttk.Label(self.status_frame, text="", foreground="red", font=('Arial', 10, 'bold'))
        self.new_msg_indicator.pack(side=tk.RIGHT, padx=10)
    
    def setup_connection_tab(self):
        """設定連線分頁"""
        # 服務發現區域
        discovery_frame = ttk.LabelFrame(self.connection_frame, text="服務發現", padding=10)
        discovery_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(discovery_frame, text="通關密語:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.passphrase_var = tk.StringVar()
        self.passphrase_entry = ttk.Entry(discovery_frame, textvariable=self.passphrase_var, width=30, show="*")
        self.passphrase_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.discover_btn = ttk.Button(discovery_frame, text="發現服務", command=self.discover_services_async)
        self.discover_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # 服務狀態顯示
        self.service_status_text = scrolledtext.ScrolledText(discovery_frame, height=5, width=50)
        self.service_status_text.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # 登入/註冊區域
        auth_frame = ttk.LabelFrame(self.connection_frame, text="身份驗證", padding=10)
        auth_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(auth_frame, text="密碼:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(auth_frame, textvariable=self.password_var, width=30, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.register_btn = ttk.Button(auth_frame, text="註冊", command=self.register_async, state='disabled')
        self.register_btn.grid(row=1, column=0, padx=5, pady=5)
        
        self.login_btn = ttk.Button(auth_frame, text="登入", command=self.login_async, state='disabled')
        self.login_btn.grid(row=1, column=1, padx=5, pady=5)
        
        self.logout_btn = ttk.Button(auth_frame, text="登出", command=self.logout, state='disabled')
        self.logout_btn.grid(row=1, column=2, padx=5, pady=5)
    
    # ... [其餘 UI setup 方法保持不變] ...
    def setup_chat_tab(self):
        """設定聊天分頁"""
        # 左側：在線使用者列表
        left_frame = ttk.Frame(self.chat_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        ttk.Label(left_frame, text="在線使用者", font=('Arial', 10, 'bold')).pack(pady=5)
        
        # 在線使用者列表框架
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.online_listbox = tk.Listbox(list_frame, width=20, height=20, yscrollcommand=scrollbar.set)
        self.online_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.online_listbox.bind('<<ListboxSelect>>', self.on_user_select)
        scrollbar.config(command=self.online_listbox.yview)
        
        # 右側：聊天區域
        right_frame = ttk.Frame(self.chat_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 聊天對象
        self.chat_target_var = tk.StringVar()
        self.chat_target_var.set("請選擇聊天對象")
        chat_header = ttk.Label(right_frame, textvariable=self.chat_target_var, font=('Arial', 12, 'bold'))
        chat_header.pack(pady=5)
        
        # 聊天記錄
        self.chat_display = scrolledtext.ScrolledText(right_frame, height=25, width=60, wrap=tk.WORD)
        self.chat_display.pack(fill=tk.BOTH, expand=True, pady=5)
        self.chat_display.config(state='disabled')
        
        # 設定聊天顯示標籤
        self.chat_display.tag_config('my_message', foreground='blue')
        self.chat_display.tag_config('other_message', foreground='green')
        self.chat_display.tag_config('system_message', foreground='gray')
        self.chat_display.tag_config('timestamp', foreground='gray', font=('Arial', 8))
        
        # 輸入區域
        input_frame = ttk.Frame(right_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var, font=('Arial', 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ttk.Button(input_frame, text="發送", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT)
    
    def setup_group_tab(self):
        """設定群組分頁"""
        # 左側：群組列表
        left_frame = ttk.Frame(self.group_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # 群組標題和創建按鈕
        header_frame = ttk.Frame(left_frame)
        header_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(header_frame, text="我的群組", font=('Arial', 10, 'bold')).pack(side=tk.LEFT)
        
        create_group_btn = ttk.Button(header_frame, text="➕", width=3, command=self.create_group_dialog)
        create_group_btn.pack(side=tk.RIGHT, padx=5)
        
        # 群組列表
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.group_listbox = tk.Listbox(list_frame, width=30, height=20, yscrollcommand=scrollbar.set)
        self.group_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.group_listbox.bind('<<ListboxSelect>>', self.on_group_select)
        scrollbar.config(command=self.group_listbox.yview)
        
        # 右側：群組聊天
        right_frame = ttk.Frame(self.group_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 群組資訊
        self.group_info_var = tk.StringVar()
        self.group_info_var.set("請選擇群組")
        group_header = ttk.Label(right_frame, textvariable=self.group_info_var, font=('Arial', 12, 'bold'))
        group_header.pack(pady=5)
        
        # 群組成員顯示
        self.group_members_var = tk.StringVar()
        members_label = ttk.Label(right_frame, textvariable=self.group_members_var, font=('Arial', 9))
        members_label.pack()
        
        # 群組聊天記錄
        self.group_chat_display = scrolledtext.ScrolledText(right_frame, height=20, width=60, wrap=tk.WORD)
        self.group_chat_display.pack(fill=tk.BOTH, expand=True, pady=5)
        self.group_chat_display.config(state='disabled')
        
        # 設定群組聊天顯示標籤
        self.group_chat_display.tag_config('my_message', foreground='blue')
        self.group_chat_display.tag_config('other_message', foreground='green')
        self.group_chat_display.tag_config('system_message', foreground='gray')
        self.group_chat_display.tag_config('timestamp', foreground='gray', font=('Arial', 8))
        
        # 群組訊息輸入
        group_input_frame = ttk.Frame(right_frame)
        group_input_frame.pack(fill=tk.X, pady=5)
        
        self.group_message_var = tk.StringVar()
        self.group_message_entry = ttk.Entry(group_input_frame, textvariable=self.group_message_var, font=('Arial', 10))
        self.group_message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.group_message_entry.bind('<Return>', lambda e: self.send_group_message())
        
        self.group_send_btn = ttk.Button(group_input_frame, text="發送", command=self.send_group_message)
        self.group_send_btn.pack(side=tk.RIGHT)
    
    def discover_services_async(self):
        """非同步發現服務"""
        passphrase = self.passphrase_var.get()
        if not passphrase:
            messagebox.showerror("錯誤", "請輸入通關密語")
            return
        
        self.discover_btn.config(state='disabled')
        self.service_status_text.delete(1.0, tk.END)
        self.service_status_text.insert(tk.END, "正在發現服務...\n")
        
        # 在背景線程執行
        threading.Thread(target=self._discover_services_thread, args=(passphrase,), daemon=True).start()
    
    def _discover_services_thread(self, passphrase):
        """服務發現線程"""
        try:
            if self.discover_services(passphrase):
                self.message_queue.put(('service_discovered', True))
            else:
                self.message_queue.put(('service_discovered', False))
        except Exception as e:
            self.logger.error(f"Service discovery error: {e}")
            self.message_queue.put(('service_discovered', False))
    
    def register_async(self):
        """非同步註冊"""
        password = self.password_var.get()
        if not password:
            messagebox.showerror("錯誤", "請輸入密碼")
            return
        
        threading.Thread(target=self._register_thread, args=(password,), daemon=True).start()
    
    def _register_thread(self, password):
        """註冊線程"""
        try:
            success = self.register(password)
            self.message_queue.put(('register_result', success))
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            self.message_queue.put(('register_result', False))
    
    def login_async(self):
        """非同步登入"""
        password = self.password_var.get()
        if not password:
            messagebox.showerror("錯誤", "請輸入密碼")
            return
        
        threading.Thread(target=self._login_thread, args=(password,), daemon=True).start()
    
    def _login_thread(self, password):
        """登入線程"""
        try:
            success = self.authenticate(password)
            self.message_queue.put(('login_result', success))
        except Exception as e:
            self.logger.error(f"Login error: {e}")
            self.message_queue.put(('login_result', False))
    
    def logout(self):
        """登出"""
        self.is_authenticated = False
        self.three_p_jwt = None
        
        # 停止所有背景線程
        self.stop_all_threads = True
        
        # 更新 UI
        self.notebook.tab(1, state='disabled')
        self.notebook.tab(2, state='disabled')
        self.register_btn.config(state='normal')
        self.login_btn.config(state='normal')
        self.logout_btn.config(state='disabled')
        self.status_var.set("已登出")
        
        # 清空列表和聊天記錄
        self.online_listbox.delete(0, tk.END)
        self.group_listbox.delete(0, tk.END)
        self.chat_history.clear()
        self.group_chat_history.clear()
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state='disabled')
        self.group_chat_display.config(state='normal')
        self.group_chat_display.delete(1.0, tk.END)
        self.group_chat_display.config(state='disabled')
        
        messagebox.showinfo("登出", "已成功登出")
    
    def on_user_select(self, event):
        """選擇使用者事件"""
        selection = self.online_listbox.curselection()
        if selection:
            user = self.online_listbox.get(selection[0])
            self.chat_target_var.set(f"與 {user} 聊天")
            self.current_chat_target = user
            self.current_chat_type = 'user'
            
            # 顯示與該使用者的聊天記錄
            self.display_chat_history(user)
    
    def on_group_select(self, event):
        """選擇群組事件"""
        selection = self.group_listbox.curselection()
        if selection:
            group_item = self.group_listbox.get(selection[0])
            # 從顯示文字中提取 group_id
            if ' (ID: ' in group_item:
                group_id = group_item.split(' (ID: ')[1].rstrip(')')
                group_name = group_item.split(' (ID: ')[0]
            else:
                # 舊格式相容
                group_id = group_item
                group_name = self.groups.get(group_id, {}).get('name', group_id)
            
            if group_id in self.groups:
                members = self.groups[group_id]['members']
                self.group_info_var.set(f"群組: {group_name}")
                self.group_members_var.set(f"成員: {', '.join(members)}")
                self.current_group_id = group_id
                self.current_group_name = group_name
                
                # 顯示群組聊天記錄
                self.display_group_chat_history(group_id)
    
    def display_chat_history(self, user_id):
        """顯示與特定使用者的聊天記錄"""
        self.chat_display.config(state='normal')
        self.chat_display.delete(1.0, tk.END)
        
        if user_id in self.chat_history:
            for msg in self.chat_history[user_id]:
                self.display_message_in_chat(msg['sender'], msg['content'], msg['timestamp'], msg['is_me'])
        
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
    
    def display_group_chat_history(self, group_id):
        """顯示群組聊天記錄"""
        self.group_chat_display.config(state='normal')
        self.group_chat_display.delete(1.0, tk.END)
        
        if group_id in self.group_chat_history:
            for msg in self.group_chat_history[group_id]:
                self.display_message_in_group_chat(msg['sender'], msg['content'], msg['timestamp'], msg['is_me'])
        
        self.group_chat_display.config(state='disabled')
        self.group_chat_display.see(tk.END)
    
    def display_message_in_chat(self, sender, content, timestamp, is_me):
        """在聊天視窗顯示訊息"""
        self.chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        if is_me:
            self.chat_display.insert(tk.END, f"我: {content}\n", 'my_message')
        else:
            self.chat_display.insert(tk.END, f"{sender}: {content}\n", 'other_message')
    
    def display_message_in_group_chat(self, sender, content, timestamp, is_me):
        """在群組聊天視窗顯示訊息"""
        self.group_chat_display.insert(tk.END, f"[{timestamp}] ", 'timestamp')
        if is_me:
            self.group_chat_display.insert(tk.END, f"我: {content}\n", 'my_message')
        else:
            self.group_chat_display.insert(tk.END, f"{sender}: {content}\n", 'other_message')
    
    def send_message(self):
        """發送個人訊息"""
        if not hasattr(self, 'current_chat_target'):
            messagebox.showwarning("警告", "請先選擇聊天對象")
            return
        
        message = self.message_var.get()
        if not message:
            return
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # 儲存到聊天記錄
        if self.current_chat_target not in self.chat_history:
            self.chat_history[self.current_chat_target] = []
        
        self.chat_history[self.current_chat_target].append({
            'sender': self.client_id,
            'content': message,
            'timestamp': timestamp,
            'is_me': True
        })
        
        # 顯示發送的訊息
        self.chat_display.config(state='normal')
        self.display_message_in_chat(self.client_id, message, timestamp, True)
        self.chat_display.config(state='disabled')
        self.chat_display.see(tk.END)
        
        # 清空輸入框
        self.message_var.set("")
        
        # 在背景發送
        threading.Thread(
            target=self._send_message_thread,
            args=(self.current_chat_target, message, False),
            daemon=True
        ).start()
    
    def send_group_message(self):
        """發送群組訊息"""
        if not hasattr(self, 'current_group_id'):
            messagebox.showwarning("警告", "請先選擇群組")
            return
        
        message = self.group_message_var.get()
        if not message:
            return
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # 儲存到群組聊天記錄
        if self.current_group_id not in self.group_chat_history:
            self.group_chat_history[self.current_group_id] = []
        
        self.group_chat_history[self.current_group_id].append({
            'sender': self.client_id,
            'content': message,
            'timestamp': timestamp,
            'is_me': True
        })
        
        # 顯示發送的訊息
        self.group_chat_display.config(state='normal')
        self.display_message_in_group_chat(self.client_id, message, timestamp, True)
        self.group_chat_display.config(state='disabled')
        self.group_chat_display.see(tk.END)
        
        # 清空輸入框
        self.group_message_var.set("")
        
        # 在背景發送
        threading.Thread(
            target=self._send_message_thread,
            args=(self.current_group_id, message, True),
            daemon=True
        ).start()
    
    def _send_message_thread(self, receiver_id, message, is_group):
        """發送訊息線程"""
        try:
            success = self.send_message_backend(receiver_id, message, is_group)
            self.message_queue.put(('send_result', (success, is_group)))
        except Exception as e:
            self.logger.error(f"Send message error: {e}")
            self.message_queue.put(('send_result', (False, is_group)))
    
    def create_group_dialog(self):
        """創建群組對話框"""
        if not self.online_clients:
            messagebox.showwarning("警告", "沒有其他在線用戶，無法創建群組")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("創建群組")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # 群組名稱
        ttk.Label(dialog, text="群組名稱:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        group_name_var = tk.StringVar()
        name_entry = ttk.Entry(dialog, textvariable=group_name_var, width=30)
        name_entry.grid(row=0, column=1, padx=10, pady=10)
        name_entry.focus()
        
        # 成員選擇
        ttk.Label(dialog, text="選擇成員:").grid(row=1, column=0, padx=10, pady=5, sticky=tk.NW)
        
        member_frame = ttk.Frame(dialog)
        member_frame.grid(row=1, column=1, padx=10, pady=5, sticky=tk.NSEW)
        
        scrollbar = ttk.Scrollbar(member_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        member_listbox = tk.Listbox(member_frame, selectmode=tk.MULTIPLE, height=10, yscrollcommand=scrollbar.set)
        member_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=member_listbox.yview)
        
        # 填充在線使用者
        for user in self.online_clients:
            if user != self.client_id:
                member_listbox.insert(tk.END, user)
        
        # 提示文字
        ttk.Label(dialog, text="(您會自動加入群組)", font=('Arial', 9), foreground='gray').grid(row=2, column=1, pady=5)
        
        def create_group():
            group_name = group_name_var.get().strip()
            if not group_name:
                messagebox.showerror("錯誤", "請輸入群組名稱", parent=dialog)
                return
            
            selected_indices = member_listbox.curselection()
            if not selected_indices:
                messagebox.showerror("錯誤", "請至少選擇一個成員", parent=dialog)
                return
                
            selected_members = [member_listbox.get(i) for i in selected_indices]
            selected_members.append(self.client_id)  # 加入自己
            
            # 在背景創建群組
            threading.Thread(
                target=self._create_group_thread,
                args=(group_name, selected_members),
                daemon=True
            ).start()
            
            dialog.destroy()
        
        # 按鈕
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="創建", command=create_group).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        # 設定對話框大小調整
        dialog.grid_rowconfigure(1, weight=1)
        dialog.grid_columnconfigure(1, weight=1)
    
    def _create_group_thread(self, group_name, members):
        """創建群組線程"""
        try:
            success, result = self.create_group(group_name, members)
            self.message_queue.put(('create_group_result', (success, result, group_name)))
        except Exception as e:
            self.logger.error(f"Create group error: {e}")
            self.message_queue.put(('create_group_result', (False, str(e), group_name)))
    
    def process_message_queue(self):
        """處理訊息佇列"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == 'service_discovered':
                    if data:
                        self.service_status_text.insert(tk.END, "✓ 服務發現成功！\n")
                        self.service_status_text.insert(tk.END, f"Server: {self.get_service_address('server')}\n")
                        self.service_status_text.insert(tk.END, f"IdP: {self.get_service_address('idp')}\n")
                        self.service_status_text.insert(tk.END, f"KACLS: {self.get_service_address('kacls')}\n")
                        self.register_btn.config(state='normal')
                        self.login_btn.config(state='normal')
                        self.status_var.set("服務已連線")
                    else:
                        self.service_status_text.insert(tk.END, "✗ 服務發現失敗\n")
                        messagebox.showerror("錯誤", "服務發現失敗，請檢查通關密語")
                    self.discover_btn.config(state='normal')
                
                elif msg_type == 'register_result':
                    if data:
                        messagebox.showinfo("成功", "註冊成功！請登入")
                    else:
                        messagebox.showerror("錯誤", "註冊失敗")
                
                elif msg_type == 'login_result':
                    if data:
                        self.notebook.tab(1, state='normal')
                        self.notebook.tab(2, state='normal')
                        self.register_btn.config(state='disabled')
                        self.login_btn.config(state='disabled')
                        self.logout_btn.config(state='normal')
                        self.status_var.set(f"已登入 - {self.client_id}")
                        messagebox.showinfo("成功", "登入成功！")
                        
                        # 啟動自動更新
                        self._start_auto_refresh()
                    else:
                        messagebox.showerror("錯誤", "登入失敗")
                
                elif msg_type == 'online_users':
                    # 更新在線使用者列表
                    current_selection = None
                    if self.online_listbox.curselection():
                        current_selection = self.online_listbox.get(self.online_listbox.curselection()[0])
                    
                    self.online_listbox.delete(0, tk.END)
                    self.online_clients = data
                    for user in data:
                        if user != self.client_id:
                            self.online_listbox.insert(tk.END, user)
                    
                    # 恢復選擇
                    if current_selection:
                        for i in range(self.online_listbox.size()):
                            if self.online_listbox.get(i) == current_selection:
                                self.online_listbox.selection_set(i)
                                break
                
                elif msg_type == 'groups_refreshed':
                    # 更新群組列表
                    current_selection = None
                    if self.group_listbox.curselection():
                        current_selection = self.group_listbox.get(self.group_listbox.curselection()[0])
                    
                    self.group_listbox.delete(0, tk.END)
                    for group_id, group_info in data.items():
                        display_text = f"{group_info['name']} (ID: {group_id})"
                        self.group_listbox.insert(tk.END, display_text)
                    
                    # 恢復選擇
                    if current_selection:
                        for i in range(self.group_listbox.size()):
                            if self.group_listbox.get(i) == current_selection:
                                self.group_listbox.selection_set(i)
                                break
                
                elif msg_type == 'send_result':
                    success, is_group = data
                    if not success:
                        messagebox.showerror("錯誤", "訊息發送失敗")
                
                elif msg_type == 'create_group_result':
                    success, result, group_name = data
                    if success:
                        messagebox.showinfo("成功", f"群組 '{group_name}' 創建成功！")
                    else:
                        messagebox.showerror("錯誤", f"創建群組失敗: {result}")
                
                elif msg_type == 'new_message':
                    # 收到新訊息
                    sender, content, timestamp, is_group, group_info = data
                    
                    if is_group:
                        group_id = group_info['group_id']
                        group_name = group_info['group_name']
                        
                        # 儲存到群組聊天記錄
                        if group_id not in self.group_chat_history:
                            self.group_chat_history[group_id] = []
                        
                        self.group_chat_history[group_id].append({
                            'sender': sender,
                            'content': content,
                            'timestamp': timestamp,
                            'is_me': False
                        })
                        
                        # 如果當前正在查看這個群組，即時顯示
                        if hasattr(self, 'current_group_id') and self.current_group_id == group_id:
                            self.group_chat_display.config(state='normal')
                            self.display_message_in_group_chat(sender, content, timestamp, False)
                            self.group_chat_display.config(state='disabled')
                            self.group_chat_display.see(tk.END)
                        
                        # 顯示通知
                        self.show_notification(f"群組 {group_name}", f"{sender}: {content}")
                    else:
                        # 儲存到個人聊天記錄
                        if sender not in self.chat_history:
                            self.chat_history[sender] = []
                        
                        self.chat_history[sender].append({
                            'sender': sender,
                            'content': content,
                            'timestamp': timestamp,
                            'is_me': False
                        })
                        
                        # 如果當前正在與該使用者聊天，即時顯示
                        if hasattr(self, 'current_chat_target') and self.current_chat_target == sender:
                            self.chat_display.config(state='normal')
                            self.display_message_in_chat(sender, content, timestamp, False)
                            self.chat_display.config(state='disabled')
                            self.chat_display.see(tk.END)
                        
                        # 顯示通知
                        self.show_notification(f"來自 {sender}", content)
                
                elif msg_type == 'group_invite':
                    # 被加入群組的通知
                    group_id, group_name, invited_by = data
                    self.show_notification("群組邀請", f"{invited_by} 將您加入群組 '{group_name}'")
                
                elif msg_type == 'new_message_count':
                    # 更新新訊息計數
                    count = data
                    if count > 0:
                        self.new_msg_indicator.config(text=f"📬 {count} 則新訊息")
                    else:
                        self.new_msg_indicator.config(text="")
                
        except queue.Empty:
            pass
        
        # 繼續排程
        self.root.after(100, self.process_message_queue)
    
    def show_notification(self, title, message):
        """顯示通知"""
        # 發出聲音
        self.root.bell()
        
        # 如果視窗不在前景，顯示系統通知
        if not self.root.focus_displayof():
            # 創建一個小的通知視窗
            notification = tk.Toplevel(self.root)
            notification.title(title)
            notification.geometry("300x100+{}+{}".format(
                self.root.winfo_x() + 50,
                self.root.winfo_y() + 50
            ))
            notification.transient(self.root)
            
            # 通知內容
            ttk.Label(notification, text=title, font=('Arial', 10, 'bold')).pack(pady=5)
            ttk.Label(notification, text=message, wraplength=280).pack(pady=5)
            
            # 3秒後自動關閉
            notification.after(3000, notification.destroy)
    
    def _start_auto_refresh(self):
        """啟動自動更新機制"""
        self.stop_all_threads = False
        
        # 啟動線上使用者自動更新
        threading.Thread(target=self._auto_refresh_online_users, daemon=True).start()
        
        # 啟動群組自動更新
        threading.Thread(target=self._auto_refresh_groups, daemon=True).start()
    
    def _auto_refresh_online_users(self):
        """自動更新在線使用者列表"""
        while self.is_authenticated and not getattr(self, 'stop_all_threads', False):
            try:
                online_clients = self.get_online_clients()
                self.message_queue.put(('online_users', online_clients))
            except Exception as e:
                self.logger.error(f"Auto refresh online users error: {e}")
            
            time.sleep(5)  # 每5秒更新一次
    
    def _auto_refresh_groups(self):
        """自動更新群組列表"""
        while self.is_authenticated and not getattr(self, 'stop_all_threads', False):
            try:
                self._get_my_groups()
                self.message_queue.put(('groups_refreshed', self.groups))
            except Exception as e:
                self.logger.error(f"Auto refresh groups error: {e}")
            
            time.sleep(10)  # 每10秒更新一次
    
    def run(self):
        """啟動 GUI"""
        self.root.mainloop()
    
    # ===== 後端方法（從原始 client.py 移植） =====
    
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
        """響應服務器廣播並獲取所有服務信息 - 加密版本"""
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
            # 使用加密通道
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
        """向IdP註冊 - 加密版本"""
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
        
        # 使用加密通道
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
    
    def authenticate(self, password):
        """向IdP認證 - 加密版本"""
        idp_host = self.get_service_address('idp')
        if not idp_host:
            self.logger.error("IdP service not discovered")
            return False
            
        request = {
            'type': 'authenticate',
            'client_id': self.client_id,
            'password': password
        }
        
        # 使用加密通道
        response = NetworkUtils.send_tcp_message(
            idp_host, 
            self.idp_port, 
            request,
            encrypt_with_public_key=self.services['idp']['public_key'],
            sign_with_private_key=self.client_private_key
        )
        
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
        """向Server註冊 - 加密版本"""
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
        
        # 使用加密通道
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
        """啟動心跳線程 - 加密版本"""
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
        """啟動訊息檢查線程 - 加密版本"""
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
                        
                        if new_messages:
                            # 更新新訊息計數
                            with self.message_lock:
                                self.new_messages.extend(new_messages)
                                self.message_queue.put(('new_message_count', len(self.new_messages)))
                            
                            # 處理每個新訊息
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
                                    
                                    # 發送通知
                                    self.message_queue.put((
                                        'group_invite',
                                        (group_id, msg_info['group_name'], msg_info['invited_by'])
                                    ))
                                else:
                                    # 自動讀取並解密訊息
                                    threading.Thread(
                                        target=self._process_new_message,
                                        args=(msg_info,),
                                        daemon=True
                                    ).start()
                            
                            # 清除已處理的訊息
                            with self.message_lock:
                                self.new_messages.clear()
                                self.message_queue.put(('new_message_count', 0))
                            
                except Exception as e:
                    self.logger.error(f"Message check failed: {e}")
                
                time.sleep(3)  # 每3秒檢查一次新訊息
        
        message_check_thread = threading.Thread(target=check_messages)
        message_check_thread.daemon = True
        message_check_thread.start()
    
    def _process_new_message(self, msg_info):
        """處理新訊息 - 加密版本"""
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
                
                if decrypted:
                    # 將訊息加入訊息佇列顯示
                    timestamp = datetime.fromisoformat(decrypted['timestamp']).strftime('%H:%M:%S')
                    
                    group_info = {}
                    if decrypted.get('group_id'):
                        group_info = {
                            'group_id': decrypted['group_id'],
                            'group_name': decrypted.get('group_name', '')
                        }
                    
                    self.message_queue.put((
                        'new_message',
                        (
                            decrypted['from'],
                            decrypted['message'],
                            timestamp,
                            bool(decrypted.get('group_id')),
                            group_info
                        )
                    ))
        except Exception as e:
            self.logger.error(f"Process new message error: {e}")
    
    def get_online_clients(self):
        """獲取在線客戶端列表 - 加密版本"""
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
        """創建群組 - 加密版本"""
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
        
    def _get_my_groups(self):
        """獲取已加入的群組 - 加密版本"""
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

    def send_message_backend(self, receiver_id, message, is_group=False):
        """發送加密訊息 - 加密版本"""
        kacls_host = self.get_service_address('kacls')
        server_host = self.get_service_address('server')
        
        if not kacls_host or not server_host:
            self.logger.error("Required services not discovered")
            return False
            
        # 生成DEK
        dek = CryptoUtils.generate_aes_key()
        
        # 加密訊息
        encrypted_message = CryptoUtils.encrypt_aes_gcm(dek, message)
        
        # 向KACLS請求包裝DEK - 使用加密通道
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
        
        # 發送加密訊息到Server - 使用加密通道
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
        """接收並解密訊息 - 加密版本"""
        server_host = self.get_service_address('server')
        kacls_host = self.get_service_address('kacls')
        
        if not server_host or not kacls_host:
            self.logger.error("Required services not discovered")
            return None
            
        # 從Server獲取訊息 - 使用加密通道
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
        
        # 向KACLS請求解包DEK - 使用加密通道
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


def main():
    if len(sys.argv) < 2:
        print("Usage: python client_gui.py <client_id>")
        sys.exit(1)
    
    client_id = sys.argv[1]
    client = CSEClientGUI(client_id)
    client.run()


if __name__ == "__main__":
    main()