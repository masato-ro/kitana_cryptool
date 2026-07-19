# RSA 金鑰產生器

安全且標準的金鑰對是進行非對稱加密與簽章驗證的前提。Kitana 提供內建的金鑰產生器，完全在本機運行，保證私鑰的安全。

## 功能規格
* **支援長度**：可選擇 **1024-bit** (一般安全)、**2048-bit** (標準安全，推薦) 或 **4096-bit** (極高安全)。
* **金鑰類型**：可在 **RSA** 與 **Ed25519** 之間切換；切換後會自動把預設輸出檔名同步更新為 RSA 的 `id_rsa.pem` / `id_rsa.pub`，或 Ed25519 的 `id_ed25519.pem` / `id_ed25519.pub`。
* **PEM 格式**：
  - 私鑰以 PKCS#8 DER 編碼的 PEM 格式儲存。
  - 公鑰以 PKCS#1 DER 編碼的 PEM 格式儲存。
* **OpenSSH 公鑰格式**：公鑰輸出檔案會直接寫成 OpenSSH 相容格式（可用於 Linux 伺服器登入 SSH 授權 `authorized_keys`）。若勾選 **Also copy OpenSSH public key**，則會把同一份內容複製到剪貼簿。

## 操作步驟
1. 切換至 **Key Generator** 分頁。
2. 選擇所需的 **Key Length**（推薦選擇 `2048`）。
3. 設定 **Private Key Output**（私鑰輸出路徑，如 `id_rsa`）。若你切換為 **Ed25519**，預設檔名會自動變成 `id_ed25519.pem`。
4. 設定 **Public Key Output**（公鑰輸出路徑，如 `id_rsa.pub`）。此檔案會直接寫成 OpenSSH 相容格式；若切換為 **Ed25519**，預設會改為 `id_ed25519.pub`。點擊 Browse 時也會以目前選擇的金鑰類型帶入對應預設檔名。
5. （選填）勾選 **Also copy OpenSSH public key**，並在右側輸入註釋（Comment），生成後會把 OpenSSH 公鑰複製到您的剪貼簿中。
6. 點擊 **Generate Key** 開始產生。
   * 注意：金鑰長度為 4096 位元時，因涉及尋找超大質數，運算可能需要數秒至數十秒，請耐心等待。
7. 產生成功後，狀態列會顯示密鑰指紋（Fingerprint）與雜湊資訊。
