# Brotherhood Communiaction 兄弟會通訊軟體

> **Secure, self‑hosted messaging & group chat with end‑to‑end encryption — written in Python 3.12**


---
## 本專案是模仿Google Client Side Encryption(CSE)打造的內網通訊軟體，要求至少3台主機組成服務維護通訊安全。
---

## 🗂️ 專案架構

```
├── server.py          # 服務協調,訊息轉送及簽發B_JWT
├── idp.py             # 用戶身分驗證與 3P_JWT 簽發
├── kacls.py           # DEK/KEK 包裝與授權 (Key Access Control)
├── client.py          # client後端
├── client_gui.py      # client前端(採CustomTkinter 圖形介面)
├── common_utils.py    # 加密 / JWT / 網路共用函式
├── requirements.txt   # Python 依賴的library(含版本)
└── assets             # 放圖形介面的配圖           
```



---

## 🚀 快速開始 

1. **下載原始碼**

   ```bash
   git clone [<repo-url](https://github.com/duduLiu8787/CSE_BrotherhoodCommunication.git)> && cd CSE_BrotherhoodCommunication
   ```
2. **建立並啟動虛擬環境(可選)**

   ```bash
   python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
   ```
3. **安裝依賴**

   ```bash
   pip install -r requirements.txt
   ```
4. **啟動三大服務 (各開一個 Terminal) — passphrase 請自訂通關密語例如"brother"**

   ```bash
   python server.py <passphrase>
   python idp.py    <passphrase>
   python kacls.py  <passphrase>
   ```
5. **啟動Client端**

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

Released under the MIT License — © 2025, DHL(duduLiu8787) & Contributors
