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
* 主要模仿Google Client Side Encryption架構分別由Server, IdP, KACLS分別掌控不同的認證，多重驗證並僅在Client端加解密。
* **加密演算法**：RSA‑2048 (簽名 / 包裝)、AES‑256‑GCM (資料)、PBKDF2‑HMAC‑SHA256 (密碼儲存)
* **多層 JWT**：

  * *3P\_JWT* — IdP 簽發，驗證用戶身份與有效期 (24h)
  * *B\_JWT* — Server 為接收者簽發，綁定 `message_id` 與 `read` 權限 (1h)
* **DEK 綁定**：KACLS 將 DEK 與 `authorized_receivers`、群組 ID 等 metadata 共同加密，避免金鑰被中途竊取後重放
* **挑戰‑回應**：Client 與 Server、IdP 均採隨機 nonce + RSA 簽名機制防止 replay

## 詳細運作流程
* Server, IdP, KACLS, Client啟動時都會生成自己的key pair。
* 除了最初服務建立外，往後所有通訊最外層都是在用Session Key加密後把key用RSA加密。
Step1. 服務建立
服務建立時Server必須先啟動，隨後Server會在內網Broacast服務訊息，服務訊息是用passphase 以AES加密，隨後IdP or KACLS也可以啟動，他們會嘗試用passphase解密訊息，解密到Server的訊息，就會嘗試透過TCP向Server傳送訊息，表明自己的身分並附上public key，
Server收到後會記錄下來，並繼續等待IdP,KACLS都加入成功，Server會協助交換資訊，至此服務正式成立，Server改為廣播供Client端加入使用服務。

Step2. Client端發現服務及註冊登入
Client端啟動後有點像IdP,KACLS，差在目前Client端啟動只要求輸入用戶名，可以在使用介面上輸入passphase，接著Client端一樣會用這個去解密看看，解出是服務就會溝通Server，Server一樣會記錄，並傳給Client端IdP,KACLS的位置，Client端接著可以設定密碼向IdP註冊，IdP會將密碼+salt並以hash紀錄下來，並保存public key，此時會簽發一個3P_JWT給client證明身分(此部分應該要刪掉，當初是測試方便弄得)，未來登入時IdP除了驗證密碼，還會利用當初紀錄的public key發起挑戰驗證(2FA)，要求Client解開挑戰驗證，都成功才會簽發3P_JWT。

Step3. 私人對話的運行
Client端登入後，Server會記錄，Client端會利用heartbeat給Server維持登入狀態，所有Client端都會定期向Server查詢在線上的人，可以選擇線上的人發起對話，輸入訊息後，會隨機生成DEK(Data Encryption Key)來加密(AES)訊息，接著把DEK傳給KACLS，KACLS會將訊息及要傳的對象用自己的KEK(KACLS Encryption Key，在啟動時KACLS隨機產生的，跟RSA key pair不同)加密包裝成w_DEK後回傳，Client收到w_DEK後會將Cipher Text+w_DEK給Server，Server會識別是要給誰的訊息，通知那個Client端，Client端收到通知後就會發起獲取訊息要求，Server會先用Client的public key發起挑戰驗證，驗證成功會繼續檢查是否有這個訊息的讀取權限，都確認後Server會簽發一個B_JWT證明Client有權限，Client端必須附上B_JWT的請求給Server，才會真的從Server獲取Cipher Text，拿到後Client端必須拿著3P_JWT, B_JWT, w_DEK給KACLS，KACLS會分別向IdP, Server詢問JWT是否確實是他們簽署的，確定後才會把w_DEK解開成DEK回傳給Client，Client才能解密。

Step4. 群組對話的建立與對話


## 📜 授權

Released under the MIT License — © 2025, DHL(duduLiu8787) & Contributors
