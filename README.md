# Threshold Signature Project

## 專案簡介
本專案使用 Python（版本 3.11.9）於 macOS 環境下開發，主要聚焦於 **Threshold Signature（門檻簽章）** 機制的實作與應用。

門檻簽章是一種分散式簽章技術，允許多個參與者共同生成一個有效的簽章。只要達到預先設定的門檻數量（threshold）成員參與簽章，即可成功簽署消息，而無需所有成員全體參與。這種機制大幅提升了系統的安全性與容錯能力。

---

## 門檻簽章機制說明

- 將私鑰分割成多份，分別分配給不同的簽章者。
- 設定一個門檻值 \( t \)，表示至少需要 \( t \) 個簽章者合作，才能產生有效簽章。
- 單個簽章者的部分簽章無法被驗證或濫用，只有收集到門檻數量的部分簽章後，才能合成最終簽章。
- 適用於多方共識、去中心化系統及提升抗攻擊能力的場景。

---

## 開發內容

目前專案中包含兩種不同門檻簽章方案的實作：

1. **基於 ECDSA (Elliptic Curve Digital Signature Algorithm)**  
   利用傳統橢圓曲線簽章演算法實現門檻簽章的分割與合成。

   File : ECDSA_Threshold_Signature

   package : ecdsa , 	pycryptodome

2. **基於 BLS (Boneh–Lynn–Shacham) 簽章**  
   利用 BLS 簽章的聚合特性實現更高效的門檻簽章，適合分散式系統與區塊鏈場景。

   File : BLS_Threshold_Signature
   
   package : py_ecc
---

## 環境需求

- Python 3.11.9
- macOS 開發系統
- 相關依賴請參考 `requirements.txt`

---

## 使用說明

1. 安裝相依套件：
   ```bash
   pip install -r requirements.txt