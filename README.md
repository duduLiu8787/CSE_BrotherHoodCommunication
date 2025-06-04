# CSE Communication System (Client‑Side Encryption)

> **Secure, self‑hosted messaging & group chat with end‑to‑end encryption — written in Python 3.12**

---

## 🗂️ 專案架構

```
├── server.py          # 服務協調與訊息轉送 (Server)
├── idp.py             # 用戶身分與 3P_JWT 簽發 (Identity Provider)
├── kacls.py           # DEK/KEK 包裝與授權 (Key Access Control)
├── client.py          # 客戶端後端邏輯 (加解密 / 網路)
├── client_gui.py      # CustomTkinter 圖形介面 (Frontend)
├── common_utils.py    # 加密 / JWT / 網路共用函式
├── requirements.txt   # Python 依賴版本鎖定
└── README.md          # 你正在看的檔案
```

各元件以 **UDP 廣播 + RSA/AES 加密通訊** 自動發現並交換公鑰，透過下列協定合作：

| 流程     | 端點                         | 重點技術                                 |
| ------ | -------------------------- | ------------------------------------ |
| 服務發現   | `server ↔ all`             | UDP Broadcast + AES‑GCM (passphrase) |
| 用戶註冊   | `client → idp`             | PBKDF2 密碼雜湊 + RSA Challenge          |
| 用戶驗證   | `client ↔ idp`             | 3P\_JWT + RSA 簽名挑戰                   |
| DEK 包裝 | `client → kacls`           | KEK 加密 & 受眾綁定                        |
| 訊息傳遞   | `client → server → client` | AES‑GCM 封包 + B\_JWT                  |

---

## 🚀 快速開始 (本機開發)

1. **下載原始碼**

   ```bash
   git clone <repo-url> && cd ClientSideEncryption
   ```
2. **建立並啟動虛擬環境**

   ```bash
   python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
   ```
3. **安裝依賴**

   ```bash
   pip install -r requirements.txt
   ```
4. **啟動三大服務 (各開一個 Terminal) — passphrase 請自訂一致**

   ```bash
   python server.py <passphrase>
   python idp.py    <passphrase>
   python kacls.py  <passphrase>
   ```
5. **啟動客戶端 GUI**

   ```bash
   python client_gui.py
   ```
6. **首次登入流程**

   1. 在 GUI 左上 *「用戶名稱」* 欄輸入帳號並設定
   2. 輸入與服務相同的 *passphrase* → 點擊 **發現服務**
   3. 輸入密碼並按 **註冊**
   4. 再次輸入密碼並按 **登入** — 完成！

## 🔒 安全設計摘要

* **加密演算法**：RSA‑2048 (簽名 / 包裝)、AES‑256‑GCM (資料)、PBKDF2‑HMAC‑SHA256 (密碼)
* **多層 JWT**：

  * *3P\_JWT* — IdP 簽發，驗證用戶身份與有效期 (24h)
  * *B\_JWT* — Server 為接收者簽發，綁定 `message_id` 與 `read` 權限 (1h)
* **DEK 綁定**：KACLS 將 DEK 與 `authorized_receivers`、群組 ID 等 metadata 共同加密，避免金鑰被中途竊取後重放
* **挑戰‑回應**：Client 與 Server、IdP 均採隨機 nonce + RSA 簽名機制防止 replay



## 📜 授權

Released under the MIT License — © 2025, DHL & Contributors
