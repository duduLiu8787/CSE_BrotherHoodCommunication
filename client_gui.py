#!/usr/bin/env python3
"""
CSE Communication System - GUI Client Frontend Component
圖形化客戶端前端應用程式 - 處理UI顯示和使用者互動
修改版：支援在GUI中輸入用戶名稱
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import sys
from datetime import datetime
from client import CSEClient

class CSEClientGUI:
    def __init__(self):
        # 初始化基本屬性（但還沒有client_id）
        self.client_id = None
        self.client = None
        
        # GUI相關屬性
        self.message_queue = queue.Queue()
        self.chat_history = {}  # {user_id: [messages]}
        self.group_chat_history = {}  # {group_id: [messages]}
        self.current_chat_target = None
        self.current_chat_type = None
        self.current_group_id = None
        self.current_group_name = None
        
        # 建立主視窗
        self.root = tk.Tk()
        self.root.title("CSE Client")
        self.root.geometry("900x700")
        
        # 設定樣式
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 初始化 UI
        self.setup_ui()
        
        # 啟動訊息處理線程
        self.root.after(100, self.process_message_queue)
        
        # 啟動定期更新線程
        self.refresh_timer = None
        
        print("Client GUI initialized")
    
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
        # 用戶登入區域
        user_frame = ttk.LabelFrame(self.connection_frame, text="用戶資訊", padding=10)
        user_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(user_frame, text="用戶名稱:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(user_frame, textvariable=self.username_var, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        self.username_entry.focus()  # 預設焦點
        
        # 用戶名稱確認按鈕
        self.set_username_btn = ttk.Button(user_frame, text="設定用戶名稱", command=self.set_username)
        self.set_username_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # 顯示當前用戶
        self.current_user_label = ttk.Label(user_frame, text="", font=('Arial', 10, 'bold'), foreground='blue')
        self.current_user_label.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # 服務發現區域（初始為禁用）
        self.discovery_frame = ttk.LabelFrame(self.connection_frame, text="服務發現", padding=10)
        self.discovery_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.discovery_frame, text="通關密語:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.passphrase_var = tk.StringVar()
        self.passphrase_entry = ttk.Entry(self.discovery_frame, textvariable=self.passphrase_var, width=30, show="*", state='disabled')
        self.passphrase_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.discover_btn = ttk.Button(self.discovery_frame, text="發現服務", command=self.discover_services_async, state='disabled')
        self.discover_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # 服務狀態顯示
        self.service_status_text = scrolledtext.ScrolledText(self.discovery_frame, height=5, width=50, state='disabled')
        self.service_status_text.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        
        # 登入/註冊區域（初始為禁用）
        self.auth_frame = ttk.LabelFrame(self.connection_frame, text="身份驗證", padding=10)
        self.auth_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(self.auth_frame, text="密碼:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.auth_frame, textvariable=self.password_var, width=30, show="*", state='disabled')
        self.password_entry.grid(row=0, column=1, padx=5, pady=5)
        
        self.register_btn = ttk.Button(self.auth_frame, text="註冊", command=self.register_async, state='disabled')
        self.register_btn.grid(row=1, column=0, padx=5, pady=5)
        
        self.login_btn = ttk.Button(self.auth_frame, text="登入", command=self.login_async, state='disabled')
        self.login_btn.grid(row=1, column=1, padx=5, pady=5)
        
        self.logout_btn = ttk.Button(self.auth_frame, text="登出", command=self.logout, state='disabled')
        self.logout_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # 認證狀態顯示
        self.auth_status_label = ttk.Label(self.auth_frame, text="", foreground="blue")
        self.auth_status_label.grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        # 設定Enter鍵綁定
        self.username_entry.bind('<Return>', lambda e: self.set_username())
        self.passphrase_entry.bind('<Return>', lambda e: self.discover_services_async())
        self.password_entry.bind('<Return>', lambda e: self.login_async())
    
    def set_username(self):
        """設定用戶名稱"""
        username = self.username_var.get().strip()
        if not username:
            messagebox.showerror("錯誤", "請輸入用戶名稱")
            return
        
        # 檢查用戶名稱是否包含非法字符
        if any(char in username for char in ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ']):
            messagebox.showerror("錯誤", "用戶名稱不能包含特殊字符或空格")
            return
        
        # 設定用戶名稱
        self.client_id = username
        self.client = CSEClient(self.client_id)
        
        # 設定回調函數
        self.client.set_callbacks(
            on_message=self.handle_new_message,
            on_group_invite=self.handle_group_invite,
            on_status_update=self.handle_status_update
        )
        
        # 更新UI
        self.current_user_label.config(text=f"當前用戶: {self.client_id}")
        self.root.title(f"CSE Client - {self.client_id}")
        
        # 禁用用戶名稱輸入，啟用其他功能
        self.username_entry.config(state='disabled')
        self.set_username_btn.config(state='disabled')
        
        # 啟用服務發現
        self.passphrase_entry.config(state='normal')
        self.discover_btn.config(state='normal')
        self.service_status_text.config(state='normal')
        
        # 將焦點移到通關密語
        self.passphrase_entry.focus()
        
        messagebox.showinfo("成功", f"用戶名稱已設定為: {self.client_id}")
    
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
    
    # ===== 事件處理方法 =====
    
    def discover_services_async(self):
        """非同步發現服務"""
        if not self.client:
            messagebox.showerror("錯誤", "請先設定用戶名稱")
            return
            
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
            if self.client.discover_services(passphrase):
                self.message_queue.put(('service_discovered', True))
            else:
                self.message_queue.put(('service_discovered', False))
        except Exception as e:
            print(f"Service discovery error: {e}")
            self.message_queue.put(('service_discovered', False))
    
    def register_async(self):
        """非同步註冊"""
        if not self.client:
            messagebox.showerror("錯誤", "請先設定用戶名稱")
            return
            
        password = self.password_var.get()
        if not password:
            messagebox.showerror("錯誤", "請輸入密碼")
            return
        
        threading.Thread(target=self._register_thread, args=(password,), daemon=True).start()
    
    def _register_thread(self, password):
        """註冊線程"""
        try:
            success = self.client.register(password)
            self.message_queue.put(('register_result', success))
        except Exception as e:
            print(f"Registration error: {e}")
            self.message_queue.put(('register_result', False))
    
    def login_async(self):
        """非同步登入"""
        if not self.client:
            messagebox.showerror("錯誤", "請先設定用戶名稱")
            return
            
        password = self.password_var.get()
        if not password:
            messagebox.showerror("錯誤", "請輸入密碼")
            return
        
        threading.Thread(target=self._login_thread, args=(password,), daemon=True).start()
    
    def _login_thread(self, password):
        """登入線程"""
        try:
            # 定義進度回調函數
            def progress_callback(status):
                self.message_queue.put(('auth_status', status))
            
            success = self.client.authenticate(password, progress_callback)
            self.message_queue.put(('login_result', success))
        except Exception as e:
            print(f"Login error: {e}")
            self.message_queue.put(('login_result', False))
    
    def logout(self):
        """登出"""
        if not self.client:
            return
            
        self.client.logout()
        
        # 停止自動更新
        if self.refresh_timer:
            self.root.after_cancel(self.refresh_timer)
            self.refresh_timer = None
        
        # 更新 UI
        self.notebook.tab(1, state='disabled')
        self.notebook.tab(2, state='disabled')
        self.register_btn.config(state='normal')
        self.login_btn.config(state='normal')
        self.logout_btn.config(state='disabled')
        self.status_var.set("已登出")
        self.auth_status_label.config(text="")
        
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
                group_name = self.client.groups.get(group_id, {}).get('name', group_id)
            
            if group_id in self.client.groups:
                members = self.client.groups[group_id]['members']
                self.group_info_var.set(f"群組: {group_name}")
                self.group_members_var.set(f"成員: {', '.join(members)}")
                self.current_group_id = group_id
                self.current_group_name = group_name
                
                # 顯示群組聊天記錄
                self.display_group_chat_history(group_id)
    
    # ===== 顯示相關方法 =====
    
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
    
    # ===== 訊息發送方法 =====
    
    def send_message(self):
        """發送個人訊息"""
        if not self.client:
            messagebox.showerror("錯誤", "請先登入")
            return
            
        if not hasattr(self, 'current_chat_target') or not self.current_chat_target:
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
        if not self.client:
            messagebox.showerror("錯誤", "請先登入")
            return
            
        if not hasattr(self, 'current_group_id') or not self.current_group_id:
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
            success = self.client.send_message(receiver_id, message, is_group)
            self.message_queue.put(('send_result', (success, is_group)))
        except Exception as e:
            print(f"Send message error: {e}")
            self.message_queue.put(('send_result', (False, is_group)))
    
    # ===== 群組管理方法 =====
    
    def create_group_dialog(self):
        """創建群組對話框"""
        if not self.client:
            messagebox.showerror("錯誤", "請先登入")
            return
            
        online_clients = self.client.get_online_clients()
        if not online_clients or len(online_clients) <= 1:
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
        for user in online_clients:
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
            success, result = self.client.create_group(group_name, members)
            self.message_queue.put(('create_group_result', (success, result, group_name)))
        except Exception as e:
            print(f"Create group error: {e}")
            self.message_queue.put(('create_group_result', (False, str(e), group_name)))
    
    # ===== 回調處理方法 =====
    
    def handle_new_message(self, message_info):
        """處理收到的新訊息"""
        sender = message_info['from']
        content = message_info['message']
        timestamp = datetime.fromisoformat(message_info['timestamp']).strftime('%H:%M:%S')
        group_id = message_info.get('group_id')
        group_name = message_info.get('group_name')
        
        if group_id:
            # 群組訊息
            group_info = {
                'group_id': group_id,
                'group_name': group_name
            }
            self.message_queue.put(('new_message', (sender, content, timestamp, True, group_info)))
        else:
            # 個人訊息
            self.message_queue.put(('new_message', (sender, content, timestamp, False, {})))
    
    def handle_group_invite(self, group_id, group_name, invited_by):
        """處理群組邀請"""
        self.message_queue.put(('group_invite', (group_id, group_name, invited_by)))
    
    def handle_status_update(self, status):
        """處理狀態更新"""
        self.message_queue.put(('status_update', status))
    
    # ===== 訊息佇列處理 =====
    
    def process_message_queue(self):
        """處理訊息佇列"""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                
                if msg_type == 'service_discovered':
                    if data:
                        self.service_status_text.insert(tk.END, "✓ 服務發現成功！\n")
                        self.service_status_text.insert(tk.END, f"Server: {self.client.get_service_address('server')}\n")
                        self.service_status_text.insert(tk.END, f"IdP: {self.client.get_service_address('idp')}\n")
                        self.service_status_text.insert(tk.END, f"KACLS: {self.client.get_service_address('kacls')}\n")
                        self.register_btn.config(state='normal')
                        self.login_btn.config(state='normal')
                        self.password_entry.config(state='normal')
                        self.status_var.set("服務已連線")
                        # 將焦點移到密碼欄位
                        self.password_entry.focus()
                    else:
                        self.service_status_text.insert(tk.END, "✗ 服務發現失敗\n")
                        messagebox.showerror("錯誤", "服務發現失敗，請檢查通關密語")
                    self.discover_btn.config(state='normal')
                
                elif msg_type == 'register_result':
                    if data:
                        messagebox.showinfo("成功", "註冊成功！請登入")
                    else:
                        messagebox.showerror("錯誤", "註冊失敗")
                
                elif msg_type == 'auth_status':
                    # 顯示認證狀態
                    self.auth_status_label.config(text=data)
                
                elif msg_type == 'login_result':
                    if data:
                        self.notebook.tab(1, state='normal')
                        self.notebook.tab(2, state='normal')
                        self.register_btn.config(state='disabled')
                        self.login_btn.config(state='disabled')
                        self.logout_btn.config(state='normal')
                        self.status_var.set(f"已登入 - {self.client_id}")
                        self.auth_status_label.config(text="")
                        messagebox.showinfo("成功", "登入成功！")
                        
                        # 啟動自動更新
                        self._start_auto_refresh()
                    else:
                        self.auth_status_label.config(text="")
                        messagebox.showerror("錯誤", "登入失敗")
                
                elif msg_type == 'online_users':
                    # 更新在線使用者列表
                    current_selection = None
                    if self.online_listbox.curselection():
                        current_selection = self.online_listbox.get(self.online_listbox.curselection()[0])
                    
                    self.online_listbox.delete(0, tk.END)
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
                        # 刷新群組列表
                        self._refresh_groups()
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
                    # 刷新群組列表
                    self._refresh_groups()
                
                elif msg_type == 'status_update':
                    # 狀態更新
                    self.status_var.set(data)
                
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
    
    # ===== 自動更新方法 =====
    
    def _start_auto_refresh(self):
        """啟動自動更新機制"""
        self._refresh_online_users()
        self._refresh_groups()
    
    def _refresh_online_users(self):
        """刷新在線使用者列表"""
        if not self.client or not self.client.is_authenticated:
            return
            
        try:
            online_clients = self.client.get_online_clients()
            self.message_queue.put(('online_users', online_clients))
        except Exception as e:
            print(f"Refresh online users error: {e}")
        
        # 排程下次更新
        self.refresh_timer = self.root.after(5000, self._refresh_online_users)  # 每5秒更新一次
    
    def _refresh_groups(self):
        """刷新群組列表"""
        if not self.client or not self.client.is_authenticated:
            return
            
        try:
            groups = self.client.get_my_groups()
            self.message_queue.put(('groups_refreshed', groups))
        except Exception as e:
            print(f"Refresh groups error: {e}")
        
        # 排程下次更新
        self.root.after(10000, self._refresh_groups)  # 每10秒更新一次
    
    def run(self):
        """啟動 GUI"""
        self.root.mainloop()


def main():
    # 不再需要命令列參數
    gui = CSEClientGUI()
    gui.run()


if __name__ == "__main__":
    main()