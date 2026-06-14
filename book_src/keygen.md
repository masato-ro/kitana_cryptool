# RSA 金鑰產生器

安全且標準的金鑰對是進行非對稱加密與簽章驗證的前提。Kitana 提供內建的金鑰產生器，完全在本機運行，保證私鑰的安全。

## 功能規格
* **支援長度**：可選擇 **1024-bit** (一般安全)、**2048-bit** (標準安全，推薦) 或 **4096-bit** (極高安全)。
* **PEM 格式**：
  - 私鑰以 PKCS#8 DER 編碼的 PEM 格式儲存。
  - 公鑰以 PKCS#1 DER 編碼的 PEM 格式儲存。
* **OpenSSH 公鑰格式**：可勾選生成標準的 OpenSSH 公鑰格式（可用於 Linux 伺服器登入 SSH 授權 `authorized_keys`）。

## 操作步驟
1. 切換至 **Key Generator** 分頁。
2. 選擇所需的 **Key Length**（推薦選擇 `2048`）。
3. 設定 **Private Key Output**（私鑰輸出路徑，如 `id_rsa`）。
4. 設定 **Public Key Output**（公鑰輸出路徑，如 `id_rsa.pub`）。
5. (選填) 勾選 **Generate OpenSSH Public Key** 並在右側輸入註釋（Comment），產生的 SSH 公鑰在金鑰生成後會自動複製到您的剪貼簿中。
6. 點擊 **Generate Key** 開始產生。
   * 注意：金鑰長度為 4096 位元時，因涉及尋找超大質數，運算可能需要數秒至數十秒，請耐心等待。
7. 產生成功後，狀態列會顯示密鑰指紋（Fingerprint）與雜湊資訊。
