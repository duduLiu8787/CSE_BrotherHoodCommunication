#!/usr/bin/env python3
"""
CSE Communication System - GUI Client Frontend Component with CustomTkinter
圖形化客戶端前端應用程式 - 使用現代化的 CustomTkinter UI
"""

import customtkinter as ctk
from tkinter import messagebox
import threading
import queue
import sys
from datetime import datetime
from client import CSEClient
from PIL import Image
from customtkinter import CTkImage

# 設定外觀模式和主題
ctk.set_appearance_mode("dark")  # 可選 "light", "dark", "system"
ctk.set_default_color_theme("blue")  # 可選 "blue", "green", "dark-blue"

class CSEClientGUI:
    def __init__(self):
        # 初始化基本屬性
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
        self.root = ctk.CTk()
        self.root.title("CSE Client")
        self.root.geometry("1000x700")
        
        # 設定視窗最小尺寸
        self.root.minsize(800, 600)
        
        # 初始化 UI
        self.setup_ui()
        
        # 啟動訊息處理線程
        self.root.after(100, self.process_message_queue)
        
        # 啟動定期更新線程
        self.refresh_timer = None
        
        print("Client GUI initialized with CustomTkinter")
    
    def setup_ui(self):
        """設定使用者介面"""
        # 創建主框架
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 創建分頁視圖
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True)
        
        # 添加分頁
        self.connection_tab = self.tabview.add("連線")
        self.chat_tab = self.tabview.add("聊天")
        self.group_tab = self.tabview.add("群組")
        
        # 設定各分頁內容
        self.setup_connection_tab()
        self.setup_chat_tab()
        self.setup_group_tab()
        
        # 初始時禁用聊天和群組分頁
        self.tabview._segmented_button.configure(state="normal")
        self.disable_tabs()
        
        # 狀態列
        self.setup_status_bar()
    
    def setup_status_bar(self):
        """設定狀態列"""
        self.status_frame = ctk.CTkFrame(self.root, height=30)
        self.status_frame.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="未連線",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="left", padx=10)
        
        # 新訊息指示器
        self.new_msg_indicator = ctk.CTkLabel(
            self.status_frame,
            text="",
            text_color="red",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.new_msg_indicator.pack(side="right", padx=10)
    
    
    def setup_connection_tab(self):
        """設定連線分頁（上中下三層：上層放圖片、中層左右分別放用戶資訊與身份驗證、下層放服務發現，且發現按鈕右側顯示結果文字）"""

        # 最外層容器
        container = ctk.CTkFrame(self.connection_tab, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # === 上層：放圖片 ===
        top_frame = ctk.CTkFrame(container, fg_color="transparent")
        top_frame.pack(fill="x", pady=(0, 10))

        # 載入並顯示圖片（自行替換路徑與大小）
        img_pil = Image.open("assets/Yakuza.jpg")
        orig_w, orig_h = img_pil.size
        self.top_image = CTkImage(dark_image=img_pil, size=(840, 350))
        top_label = ctk.CTkLabel(top_frame, image=self.top_image, text="")
        top_label.pack()

        # === 中層：左右佈局 ─ 左側放用戶資訊，右側放身份驗證 ===
        middle_frame = ctk.CTkFrame(container, fg_color="transparent")
        middle_frame.pack(fill="x", pady=(0, 10))

        # 左側：用戶資訊
        user_frame = ctk.CTkFrame(middle_frame, fg_color="transparent")
        user_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        ctk.CTkLabel(
            user_frame,
            text="用戶資訊",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(10, 5))

        username_container = ctk.CTkFrame(user_frame, fg_color="transparent")
        username_container.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(username_container, text="用戶名稱:").pack(side="left", padx=(0, 10))
        self.username_entry = ctk.CTkEntry(
            username_container,
            placeholder_text="請輸入用戶名稱",
            width=200
        )
        self.username_entry.pack(side="left", padx=(0, 10))
        self.username_entry.focus()
        self.set_username_btn = ctk.CTkButton(
            username_container,
            text="設定用戶名稱",
            command=self.set_username,
            width=120
        )
        self.set_username_btn.pack(side="left")

        self.current_user_label = ctk.CTkLabel(
            user_frame,
            text="",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("blue", "lightblue")
        )
        self.current_user_label.pack(pady=(5, 10))

        # 右側：身份驗證
        self.auth_frame = ctk.CTkFrame(middle_frame, fg_color="transparent")
        self.auth_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        ctk.CTkLabel(
            self.auth_frame,
            text="身份驗證",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(pady=(10, 5))

        password_container = ctk.CTkFrame(self.auth_frame, fg_color="transparent")
        password_container.pack(fill="x", padx=20, pady=10)
        ctk.CTkLabel(password_container, text="密碼:").pack(side="left", padx=(0, 10))
        self.password_entry = ctk.CTkEntry(
            password_container,
            placeholder_text="請輸入密碼",
            show="*",
            width=200,
            state="disabled"
        )
        self.password_entry.pack(side="left", padx=(0, 10))

        button_container = ctk.CTkFrame(self.auth_frame, fg_color="transparent")
        button_container.pack(pady=10)
        self.register_btn = ctk.CTkButton(
            button_container,
            text="註冊",
            command=self.register_async,
            width=100,
            state="disabled"
        )
        self.register_btn.pack(side="left", padx=5)
        self.login_btn = ctk.CTkButton(
            button_container,
            text="登入",
            command=self.login_async,
            width=100,
            state="disabled"
        )
        self.login_btn.pack(side="left", padx=5)
        self.logout_btn = ctk.CTkButton(
            button_container,
            text="登出",
            command=self.logout,
            width=100,
            state="disabled",
            fg_color="red",
            hover_color="darkred"
        )
        self.logout_btn.pack(side="left", padx=5)

        self.auth_status_label = ctk.CTkLabel(
            self.auth_frame,
            text="",
            text_color=("blue", "lightblue")
        )
        self.auth_status_label.pack(pady=(5, 10))

        # 綁定 Enter 鍵
        self.username_entry.bind('<Return>', lambda e: self.set_username())
        self.password_entry.bind('<Return>', lambda e: self.login_async())

        # === 下層：服務發現 ===
        self.discovery_frame = ctk.CTkFrame(container, fg_color="transparent")
        self.discovery_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(
            self.discovery_frame,
            text="服務發現",
            font=ctk.CTkFont(size=16, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=200, pady=(10, 5))

        # 通關密語輸入與按鈕（放在 grid row=1, column=0）
        passphrase_container = ctk.CTkFrame(self.discovery_frame, fg_color="transparent")
        passphrase_container.grid(row=1, column=0, sticky="w", padx=(20, 10), pady=10)
        ctk.CTkLabel(passphrase_container, text="通關密語:").pack(side="left", padx=(0, 10))
        self.passphrase_entry = ctk.CTkEntry(
            passphrase_container,
            placeholder_text="請輸入通關密語",
            show="*",
            width=200,
            state="disabled"
        )
        self.passphrase_entry.pack(side="left", padx=(0, 10))
        self.discover_btn = ctk.CTkButton(
            passphrase_container,
            text="發現服務",
            command=self.discover_services_async,
            width=120,
            state="disabled"
        )
        self.discover_btn.pack(side="left")

        # 服務狀態文字框放在按鈕右邊（grid row=1, column=1）
        self.service_status_text = ctk.CTkTextbox(
            self.discovery_frame,
            height=100,
            state="disabled",
            fg_color="transparent",
            border_width=0
        )
        self.service_status_text.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=10)

        # 讓 column=1 可拉伸
        self.discovery_frame.grid_columnconfigure(1, weight=1)

        # 綁定 Enter
        self.passphrase_entry.bind('<Return>', lambda e: self.discover_services_async())


    def setup_chat_tab(self):
        """設定聊天分頁"""
        # 主要容器
        chat_container = ctk.CTkFrame(self.chat_tab)
        chat_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 左側：在線使用者列表
        left_frame = ctk.CTkFrame(chat_container, width=200)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        left_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            left_frame,
            text="在線使用者",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=10)
        
        # 使用 CTkScrollableFrame 替代 Listbox
        self.online_users_frame = ctk.CTkScrollableFrame(left_frame)
        self.online_users_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.online_user_buttons = {}  # 儲存使用者按鈕
        
        # 右側：聊天區域
        right_frame = ctk.CTkFrame(chat_container)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # 聊天對象標題
        self.chat_target_label = ctk.CTkLabel(
            right_frame,
            text="請選擇聊天對象",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.chat_target_label.pack(pady=10)
        
        # 聊天記錄顯示
        self.chat_display = ctk.CTkTextbox(
            right_frame,
            wrap="word",
            state="disabled"
        )
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # 輸入區域
        input_frame = ctk.CTkFrame(right_frame)
        input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.message_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="輸入訊息...",
            font=ctk.CTkFont(size=12)
        )
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_btn = ctk.CTkButton(
            input_frame,
            text="發送",
            command=self.send_message,
            width=80
        )
        self.send_btn.pack(side="right")
    
    def setup_group_tab(self):
        """設定群組分頁"""
        # 主要容器
        group_container = ctk.CTkFrame(self.group_tab)
        group_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # 左側：群組列表
        left_frame = ctk.CTkFrame(group_container, width=250)
        left_frame.pack(side="left", fill="y", padx=(0, 10))
        left_frame.pack_propagate(False)
        
        # 群組標題和創建按鈕
        header_frame = ctk.CTkFrame(left_frame)
        header_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            header_frame,
            text="我的群組",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(side="left")
        
        self.create_group_btn = ctk.CTkButton(
            header_frame,
            text="➕",
            width=30,
            height=30,
            command=self.create_group_dialog
        )
        self.create_group_btn.pack(side="right")
        
        # 群組列表
        self.group_list_frame = ctk.CTkScrollableFrame(left_frame)
        self.group_list_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.group_buttons = {}  # 儲存群組按鈕
        
        # 右側：群組聊天
        right_frame = ctk.CTkFrame(group_container)
        right_frame.pack(side="right", fill="both", expand=True)
        
        # 群組資訊
        self.group_info_label = ctk.CTkLabel(
            right_frame,
            text="請選擇群組",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.group_info_label.pack(pady=5)
        
        self.group_members_label = ctk.CTkLabel(
            right_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.group_members_label.pack(pady=(0, 10))
        
        # 群組聊天記錄
        self.group_chat_display = ctk.CTkTextbox(
            right_frame,
            wrap="word",
            state="disabled"
        )
        self.group_chat_display.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # 群組訊息輸入
        group_input_frame = ctk.CTkFrame(right_frame)
        group_input_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.group_message_entry = ctk.CTkEntry(
            group_input_frame,
            placeholder_text="輸入群組訊息...",
            font=ctk.CTkFont(size=12)
        )
        self.group_message_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.group_message_entry.bind('<Return>', lambda e: self.send_group_message())
        
        self.group_send_btn = ctk.CTkButton(
            group_input_frame,
            text="發送",
            command=self.send_group_message,
            width=80
        )
        self.group_send_btn.pack(side="right")
    
    def disable_tabs(self):
        """禁用聊天和群組分頁"""
        # CustomTkinter 沒有直接禁用分頁的方法，所以我們禁用內容
        for widget in self.chat_tab.winfo_children():
            self.set_widget_state(widget, "disabled")
        for widget in self.group_tab.winfo_children():
            self.set_widget_state(widget, "disabled")
    
    def enable_tabs(self):
        """啟用聊天和群組分頁"""
        for widget in self.chat_tab.winfo_children():
            self.set_widget_state(widget, "normal")
        for widget in self.group_tab.winfo_children():
            self.set_widget_state(widget, "normal")
    
    def set_widget_state(self, widget, state):
        """遞迴設定 widget 狀態"""
        try:
            widget.configure(state=state)
        except:
            pass
        for child in widget.winfo_children():
            self.set_widget_state(child, state)
    
    # ===== 事件處理方法 =====
    
    def set_username(self):
        """設定用戶名稱"""
        username = self.username_entry.get().strip()
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
        self.current_user_label.configure(text=f"當前用戶: {self.client_id}")
        self.root.title(f"CSE Client - {self.client_id}")
        
        # 禁用用戶名稱輸入，啟用其他功能
        self.username_entry.configure(state="disabled")
        self.set_username_btn.configure(state="disabled")
        
        # 啟用服務發現
        self.passphrase_entry.configure(state="normal")
        self.discover_btn.configure(state="normal")
        self.service_status_text.configure(state="normal")
        
        # 將焦點移到通關密語
        self.passphrase_entry.focus()
        
        messagebox.showinfo("成功", f"用戶名稱已設定為: {self.client_id}")
    
    def discover_services_async(self):
        """非同步發現服務"""
        if not self.client:
            messagebox.showerror("錯誤", "請先設定用戶名稱")
            return
            
        passphrase = self.passphrase_entry.get()
        if not passphrase:
            messagebox.showerror("錯誤", "請輸入通關密語")
            return
        
        self.discover_btn.configure(state="disabled")
        self.service_status_text.delete("1.0", "end")
        self.service_status_text.insert("1.0", "正在發現服務...\n")
        
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
            
        password = self.password_entry.get()
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
            
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("錯誤", "請輸入密碼")
            return
        
        threading.Thread(target=self._login_thread, args=(password,), daemon=True).start()
    
    def _login_thread(self, password):
        """登入線程"""
        try:
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
        self.disable_tabs()
        self.register_btn.configure(state="normal")
        self.login_btn.configure(state="normal")
        self.logout_btn.configure(state="disabled")
        self.status_label.configure(text="已登出")
        self.auth_status_label.configure(text="")
        
        # 清空列表和聊天記錄
        self.clear_online_users()
        self.clear_groups()
        self.chat_history.clear()
        self.group_chat_history.clear()
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        self.chat_display.configure(state="disabled")
        self.group_chat_display.configure(state="normal")
        self.group_chat_display.delete("1.0", "end")
        self.group_chat_display.configure(state="disabled")
        
        messagebox.showinfo("登出", "已成功登出")
    
    def on_user_select(self, user):
        """選擇使用者事件"""
        self.chat_target_label.configure(text=f"與 {user} 聊天")
        self.current_chat_target = user
        self.current_chat_type = 'user'
        
        # 顯示與該使用者的聊天記錄
        self.display_chat_history(user)
    
    def on_group_select(self, group_id, group_name):
        """選擇群組事件"""
        if group_id in self.client.groups:
            members = self.client.groups[group_id]['members']
            self.group_info_label.configure(text=f"群組: {group_name}")
            self.group_members_label.configure(text=f"成員: {', '.join(members)}")
            self.current_group_id = group_id
            self.current_group_name = group_name
            
            # 顯示群組聊天記錄
            self.display_group_chat_history(group_id)
    
    # ===== 顯示相關方法 =====
    
    def display_chat_history(self, user_id):
        """顯示與特定使用者的聊天記錄"""
        self.chat_display.configure(state="normal")
        self.chat_display.delete("1.0", "end")
        
        if user_id in self.chat_history:
            for msg in self.chat_history[user_id]:
                self.display_message_in_chat(msg['sender'], msg['content'], msg['timestamp'], msg['is_me'])
        
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")
    
    def display_group_chat_history(self, group_id):
        """顯示群組聊天記錄"""
        self.group_chat_display.configure(state="normal")
        self.group_chat_display.delete("1.0", "end")
        
        if group_id in self.group_chat_history:
            for msg in self.group_chat_history[group_id]:
                self.display_message_in_group_chat(msg['sender'], msg['content'], msg['timestamp'], msg['is_me'])
        
        self.group_chat_display.configure(state="disabled")
        self.group_chat_display.see("end")
    
    def display_message_in_chat(self, sender, content, timestamp, is_me):
        """在聊天視窗顯示訊息"""
        color = "blue" if is_me else "green"
        sender_text = "我" if is_me else sender
        self.chat_display.insert("end", f"[{timestamp}] {sender_text}: {content}\n")
    
    def display_message_in_group_chat(self, sender, content, timestamp, is_me):
        """在群組聊天視窗顯示訊息"""
        color = "blue" if is_me else "green"
        sender_text = "我" if is_me else sender
        self.group_chat_display.insert("end", f"[{timestamp}] {sender_text}: {content}\n")
    
    # ===== 訊息發送方法 =====
    
    def send_message(self):
        """發送個人訊息"""
        if not self.client:
            messagebox.showerror("錯誤", "請先登入")
            return
            
        if not hasattr(self, 'current_chat_target') or not self.current_chat_target:
            messagebox.showwarning("警告", "請先選擇聊天對象")
            return
        
        message = self.message_entry.get()
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
        self.chat_display.configure(state="normal")
        self.display_message_in_chat(self.client_id, message, timestamp, True)
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")
        
        # 清空輸入框
        self.message_entry.delete(0, "end")
        
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
        
        message = self.group_message_entry.get()
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
        self.group_chat_display.configure(state="normal")
        self.display_message_in_group_chat(self.client_id, message, timestamp, True)
        self.group_chat_display.configure(state="disabled")
        self.group_chat_display.see("end")
        
        # 清空輸入框
        self.group_message_entry.delete(0, "end")
        
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
            
        # 創建對話框視窗
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("創建群組")
        dialog.geometry("500x500")
        dialog.transient(self.root)
        dialog.update_idletasks() 
        dialog.grab_set()
        
        # 中心化視窗
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (400 // 2)
        dialog.geometry(f"500x500+{x}+{y}")
        
        # 主框架
        main_frame = ctk.CTkFrame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # 群組名稱
        ctk.CTkLabel(
            main_frame,
            text="群組名稱:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=(0, 5))
        
        group_name_entry = ctk.CTkEntry(
            main_frame,
            placeholder_text="輸入群組名稱",
            width=300
        )
        group_name_entry.pack(fill="x", pady=(0, 20))
        group_name_entry.focus()
        
        # 成員選擇
        ctk.CTkLabel(
            main_frame,
            text="選擇成員:",
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", pady=(0, 5))
        
        # 成員列表容器
        member_scroll = ctk.CTkScrollableFrame(main_frame, height=200)
        member_scroll.pack(fill="both", expand=True, pady=(0, 10))
        
        # 使用字典儲存checkbox變數
        member_vars = {}
        
        for user in online_clients:
            if user != self.client_id:
                var = ctk.BooleanVar()
                member_vars[user] = var
                
                checkbox = ctk.CTkCheckBox(
                    member_scroll,
                    text=user,
                    variable=var,
                    font=ctk.CTkFont(size=12)
                )
                checkbox.pack(anchor="w", pady=2)
        
        # 提示文字
        ctk.CTkLabel(
            main_frame,
            text="(您會自動加入群組)",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=5)
        
        def create_group():
            group_name = group_name_entry.get().strip()
            if not group_name:
                messagebox.showerror("錯誤", "請輸入群組名稱", parent=dialog)
                return
            
            # 獲取選中的成員
            selected_members = [user for user, var in member_vars.items() if var.get()]
            
            if not selected_members:
                messagebox.showerror("錯誤", "請至少選擇一個成員", parent=dialog)
                return
            
            selected_members.append(self.client_id)  # 加入自己
            
            # 在背景創建群組
            threading.Thread(
                target=self._create_group_thread,
                args=(group_name, selected_members),
                daemon=True
            ).start()
            
            dialog.destroy()
        
        # 按鈕框架
        btn_frame = ctk.CTkFrame(main_frame)
        btn_frame.pack(side="bottom", fill="x", pady=(10, 0))
        
        ctk.CTkButton(
            btn_frame,
            text="創建",
            command=create_group,
            width=100
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(
            btn_frame,
            text="取消",
            command=dialog.destroy,
            width=100,
            fg_color="gray",
            hover_color="darkgray"
        ).pack(side="left")
    
    def _create_group_thread(self, group_name, members):
        """創建群組線程"""
        try:
            success, result = self.client.create_group(group_name, members)
            self.message_queue.put(('create_group_result', (success, result, group_name)))
        except Exception as e:
            print(f"Create group error: {e}")
            self.message_queue.put(('create_group_result', (False, str(e), group_name)))
    
    # ===== UI 更新方法 =====
    
    def clear_online_users(self):
        """清空在線使用者列表"""
        for button in self.online_user_buttons.values():
            button.destroy()
        self.online_user_buttons.clear()
    
    def update_online_users(self, users):
        """更新在線使用者列表"""
        # 清除現有按鈕
        self.clear_online_users()
        
        # 創建新按鈕
        for user in users:
            if user != self.client_id:
                btn = ctk.CTkButton(
                    self.online_users_frame,
                    text=user,
                    command=lambda u=user: self.on_user_select(u),
                    height=35,
                    fg_color=("gray75", "gray25"),
                    hover_color=("gray60", "gray35")
                )
                btn.pack(fill="x", padx=5, pady=2)
                self.online_user_buttons[user] = btn
    
    def clear_groups(self):
        """清空群組列表"""
        for button in self.group_buttons.values():
            button.destroy()
        self.group_buttons.clear()
    
    def update_groups(self, groups):
        """更新群組列表"""
        # 清除現有按鈕
        self.clear_groups()
        
        # 創建新按鈕
        for group_id, group_info in groups.items():
            btn = ctk.CTkButton(
                self.group_list_frame,
                text=f"{group_info['name']}",
                command=lambda gid=group_id, gname=group_info['name']: self.on_group_select(gid, gname),
                height=35,
                fg_color=("gray75", "gray25"),
                hover_color=("gray60", "gray35")
            )
            btn.pack(fill="x", padx=5, pady=2)
            self.group_buttons[group_id] = btn
    
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
                        self.service_status_text.insert("end", "✓ 服務發現成功！\n")
                        self.service_status_text.insert("end", f"Server: {self.client.get_service_address('server')}\n")
                        self.service_status_text.insert("end", f"IdP: {self.client.get_service_address('idp')}\n")
                        self.service_status_text.insert("end", f"KACLS: {self.client.get_service_address('kacls')}\n")
                        self.register_btn.configure(state="normal")
                        self.login_btn.configure(state="normal")
                        self.password_entry.configure(state="normal")
                        self.status_label.configure(text="服務已連線")
                        self.password_entry.focus()
                    else:
                        self.service_status_text.insert("end", "✗ 服務發現失敗\n")
                        messagebox.showerror("錯誤", "服務發現失敗，請檢查通關密語")
                    self.discover_btn.configure(state="normal")
                
                elif msg_type == 'register_result':
                    if data:
                        messagebox.showinfo("成功", "註冊成功！請登入")
                    else:
                        messagebox.showerror("錯誤", "註冊失敗")
                
                elif msg_type == 'auth_status':
                    self.auth_status_label.configure(text=data)
                
                elif msg_type == 'login_result':
                    if data:
                        self.enable_tabs()
                        self.register_btn.configure(state="disabled")
                        self.login_btn.configure(state="disabled")
                        self.logout_btn.configure(state="normal")
                        self.status_label.configure(text=f"已登入 - {self.client_id}")
                        self.auth_status_label.configure(text="")
                        messagebox.showinfo("成功", "登入成功！")
                        
                        # 切換到聊天分頁
                        self.tabview.set("聊天")
                        
                        # 啟動自動更新
                        self._start_auto_refresh()
                    else:
                        self.auth_status_label.configure(text="")
                        messagebox.showerror("錯誤", "登入失敗")
                
                elif msg_type == 'online_users':
                    self.update_online_users(data)
                
                elif msg_type == 'groups_refreshed':
                    self.update_groups(data)
                
                elif msg_type == 'send_result':
                    success, is_group = data
                    if not success:
                        messagebox.showerror("錯誤", "訊息發送失敗")
                
                elif msg_type == 'create_group_result':
                    success, result, group_name = data
                    if success:
                        messagebox.showinfo("成功", f"群組 '{group_name}' 創建成功！")
                        self._refresh_groups()
                    else:
                        messagebox.showerror("錯誤", f"創建群組失敗: {result}")
                
                elif msg_type == 'new_message':
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
                            self.group_chat_display.configure(state="normal")
                            self.display_message_in_group_chat(sender, content, timestamp, False)
                            self.group_chat_display.configure(state="disabled")
                            self.group_chat_display.see("end")
                        
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
                            self.chat_display.configure(state="normal")
                            self.display_message_in_chat(sender, content, timestamp, False)
                            self.chat_display.configure(state="disabled")
                            self.chat_display.see("end")
                        
                        # 顯示通知
                        self.show_notification(f"來自 {sender}", content)
                
                elif msg_type == 'group_invite':
                    group_id, group_name, invited_by = data
                    self.show_notification("群組邀請", f"{invited_by} 將您加入群組 '{group_name}'")
                    self._refresh_groups()
                
                elif msg_type == 'status_update':
                    self.status_label.configure(text=data)
                
        except queue.Empty:
            pass
        
        # 繼續排程
        self.root.after(100, self.process_message_queue)
    
    def show_notification(self, title, message):
        """顯示通知"""
        # 發出聲音
        self.root.bell()
        
        # 更新新訊息指示器
        self.new_msg_indicator.configure(text="● 新訊息")
        
        # 5秒後清除指示器
        self.root.after(5000, lambda: self.new_msg_indicator.configure(text=""))
        
        # 如果視窗不在前景，顯示系統通知
        if not self.root.focus_displayof():
            # 創建一個小的通知視窗
            notification = ctk.CTkToplevel(self.root)
            notification.title(title)
            notification.geometry("350x120")
            notification.transient(self.root)
            
            # 設定通知視窗位置（右下角）
            notification.update_idletasks()
            x = notification.winfo_screenwidth() - 370
            y = notification.winfo_screenheight() - 170
            notification.geometry(f"350x120+{x}+{y}")
            
            # 通知內容
            notif_frame = ctk.CTkFrame(notification)
            notif_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            ctk.CTkLabel(
                notif_frame,
                text=title,
                font=ctk.CTkFont(size=14, weight="bold")
            ).pack(pady=(0, 5))
            
            ctk.CTkLabel(
                notif_frame,
                text=message,
                wraplength=320
            ).pack()
            
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
        self.refresh_timer = self.root.after(5000, self._refresh_online_users)
    
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
        self.root.after(10000, self._refresh_groups)
    
    def run(self):
        """啟動 GUI"""
        self.root.mainloop()


def main():
    # 創建並執行 GUI
    gui = CSEClientGUI()
    gui.run()


if __name__ == "__main__":
    main()
