#!/usr/bin/env python3
"""
BLS Threshold Signature Implementation
使用BLS簽名和Shamir秘密分享實現門檻簽名
BLS簽名的優勢：
1. 簽名聚合更簡單（直接相加）
2. 不需要所有參與者使用相同的隨機數
3. 更適合門檻和多重簽名場景
"""

import hashlib
import secrets
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from py_ecc.bn128 import G1, G2, multiply, add, pairing, curve_order
from py_ecc.utils import prime_field_inv


@dataclass
class SecretShare:
    """秘密分享的數據結構"""
    x: int  # 分享者的ID
    y: int  # 分享的值


@dataclass
class BLSPartialSignature:
    """BLS部分簽名的數據結構"""
    signer_id: int
    signature: Tuple  # G1上的點


class ShamirSecretSharing:
    """Shamir秘密分享方案實作"""
    
    def __init__(self, threshold: int, num_parties: int):
        self.threshold = threshold
        self.num_parties = num_parties
        self.prime = curve_order  # 使用BN128曲線的order
    
    def generate_polynomial(self, secret: int) -> List[int]:
        """生成t-1次多項式，常數項為秘密"""
        coefficients = [secret]
        for _ in range(self.threshold - 1):
            coefficients.append(secrets.randbelow(self.prime))
        return coefficients
    
    def evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """計算多項式在x點的值"""
        result = 0
        for i, coeff in enumerate(coefficients):
            result = (result + coeff * pow(x, i, self.prime)) % self.prime
        return result
    
    def create_shares(self, secret: int) -> List[SecretShare]:
        """創建秘密分享"""
        coefficients = self.generate_polynomial(secret)
        shares = []
        
        for i in range(1, self.num_parties + 1):
            y = self.evaluate_polynomial(coefficients, i)
            shares.append(SecretShare(x=i, y=y))
        
        return shares
    
    def lagrange_coefficient(self, shares: List[SecretShare], i: int) -> int:
        """計算拉格朗日插值係數"""
        xi = shares[i].x
        numerator = 1
        denominator = 1
        
        for j, share in enumerate(shares):
            if i != j:
                xj = share.x
                numerator = (numerator * (-xj)) % self.prime
                denominator = (denominator * (xi - xj)) % self.prime
        
        return (numerator * prime_field_inv(denominator, self.prime)) % self.prime


def normalize_point(point):
    """正規化橢圓曲線點"""
    if len(point) == 3 and point[2] != 0:
        # 如果是射影座標，轉換為仿射座標
        z_inv = prime_field_inv(point[2], curve_order)
        return (point[0] * z_inv % curve_order, point[1] * z_inv % curve_order)
    return point


def hash_to_g1(message: bytes) -> Tuple:
    """將消息哈希到G1群上的一個點"""
    # 簡化的hash-to-curve實作
    # 在生產環境中應該使用標準的hash-to-curve算法
    hash_bytes = hashlib.sha256(message).digest()
    
    # 將哈希值轉換為標量
    scalar = int.from_bytes(hash_bytes, 'big') % curve_order
    
    # 將標量乘以G1生成元得到點
    point = multiply(G1, scalar)
    return point


class BLSThresholdSignature:
    """BLS門檻簽名系統實作"""
    
    def __init__(self, threshold: int, num_parties: int):
        self.threshold = threshold
        self.num_parties = num_parties
        self.sss = ShamirSecretSharing(threshold, num_parties)
        
        # 生成主私鑰
        self.master_private_key = secrets.randbelow(curve_order)
        
        # 計算公鑰：PK = sk * G2
        self.public_key = multiply(G2, self.master_private_key)
        
        # 分發私鑰分享
        self.private_shares = self.sss.create_shares(self.master_private_key)
        
        # 生成每個參與者的公鑰分享（用於驗證部分簽名）
        self.public_key_shares = []
        for share in self.private_shares:
            pk_share = multiply(G2, share.y)
            self.public_key_shares.append((share.x, pk_share))
        
        print(f"BLS門檻簽名系統初始化完成:")
        print(f"- 門檻值: {threshold}")
        print(f"- 參與者數量: {num_parties}")
        print(f"- 主私鑰: {hex(self.master_private_key)[:20]}...")
        print(f"- 公鑰: {self.format_point(self.public_key)}")
    
    def format_point(self, point: Tuple) -> str:
        """格式化點的顯示"""
        try:
            if isinstance(point, tuple) and len(point) >= 2:
                if len(point) == 3:
                    return f"({hex(int(point[0]))[:10]}..., {hex(int(point[1]))[:10]}..., {hex(int(point[2]))[:10]}...)"
                else:
                    return f"({hex(int(point[0]))[:10]}..., {hex(int(point[1]))[:10]}...)"
            else:
                return str(point)[:50] + "..."
        except:
            return str(point)[:50] + "..."
    
    def get_private_share(self, party_id: int) -> SecretShare:
        """獲取指定參與者的私鑰分享"""
        if party_id < 1 or party_id > self.num_parties:
            raise ValueError(f"參與者ID必須在1到{self.num_parties}之間")
        return self.private_shares[party_id - 1]
    
    def get_public_key_share(self, party_id: int) -> Tuple:
        """獲取指定參與者的公鑰分享"""
        if party_id < 1 or party_id > self.num_parties:
            raise ValueError(f"參與者ID必須在1到{self.num_parties}之間")
        return self.public_key_shares[party_id - 1][1]
    
    def create_partial_signature(self, party_id: int, message: bytes) -> BLSPartialSignature:
        """創建BLS部分簽名"""
        private_share = self.get_private_share(party_id)
        
        # 將消息哈希到G1
        h = hash_to_g1(message)
        
        # 計算部分簽名：σ_i = sk_i * H(m)
        partial_signature = multiply(h, private_share.y)
        
        return BLSPartialSignature(signer_id=party_id, signature=partial_signature)
    
    def verify_partial_signature(self, partial_sig: BLSPartialSignature, message: bytes) -> bool:
        """驗證部分簽名"""
        try:
            # 獲取對應的公鑰分享
            pk_share = self.get_public_key_share(partial_sig.signer_id)
            
            # 將消息哈希到G1
            h = hash_to_g1(message)
            
            # 驗證：e(σ_i, G2) = e(H(m), pk_i)
            lhs = pairing(G2, partial_sig.signature)
            rhs = pairing(pk_share, h)
            
            return lhs == rhs
        except Exception as e:
            print(f"部分簽名驗證失敗: {e}")
            return False
    
    def combine_signatures(self, partial_sigs: List[BLSPartialSignature]) -> Tuple:
        """組合部分簽名為完整簽名"""
        if len(partial_sigs) < self.threshold:
            raise ValueError(f"需要至少 {self.threshold} 個部分簽名")
        
        # 只使用前threshold個簽名
        selected_sigs = partial_sigs[:self.threshold]
        
        # 創建用於拉格朗日插值的分享（使用簽名者ID）
        shares = []
        for sig in selected_sigs:
            shares.append(SecretShare(x=sig.signer_id, y=0))  # y值在這裡不重要，只需要x值
        
        # 計算拉格朗日係數並組合簽名
        combined_signature = None
        
        for i, sig in enumerate(selected_sigs):
            # 計算拉格朗日係數
            coeff = self.sss.lagrange_coefficient(shares, i)
            
            # 將部分簽名乘以係數
            weighted_sig = multiply(sig.signature, coeff)
            
            # 累加到組合簽名
            if combined_signature is None:
                combined_signature = weighted_sig
            else:
                combined_signature = add(combined_signature, weighted_sig)
        
        return combined_signature
    
    def verify_signature(self, signature: Tuple, message: bytes) -> bool:
        """驗證BLS簽名"""
        try:
            # 將消息哈希到G1
            h = hash_to_g1(message)
            
            # 驗證：e(σ, G2) = e(H(m), PK)
            lhs = pairing(G2, signature)
            rhs = pairing(self.public_key, h)
            
            return lhs == rhs
        except Exception as e:
            print(f"簽名驗證失敗: {e}")
            return False
    
    def simulate_signing_process(self, message: bytes, signers: List[int]) -> bool:
        """模擬完整的BLS門檻簽名流程"""
        print(f"\n開始BLS門檻簽名流程:")
        print(f"消息: {message.decode('utf-8', errors='ignore')}")
        print(f"參與簽名者: {signers}")
        
        if len(signers) < self.threshold:
            print(f"❌ 簽名者數量不足，需要至少 {self.threshold} 個")
            return False
        
        # 1. 創建部分簽名
        print("\n步驟1: 創建部分簽名")
        partial_signatures = []
        for signer_id in signers:
            partial_sig = self.create_partial_signature(signer_id, message)
            partial_signatures.append(partial_sig)
            print(f"  參與者 {signer_id}: {self.format_point(partial_sig.signature)}")
            
            # 驗證部分簽名
            is_partial_valid = self.verify_partial_signature(partial_sig, message)
            print(f"    部分簽名驗證: {'✅' if is_partial_valid else '❌'}")
        
        # 2. 組合簽名
        print("\n步驟2: 組合部分簽名")
        try:
            combined_signature = self.combine_signatures(partial_signatures)
            print(f"  組合簽名: {self.format_point(combined_signature)}")
        except Exception as e:
            print(f"❌ 簽名組合失敗: {e}")
            return False
        
        # 3. 驗證最終簽名
        print("\n步驟3: 驗證最終簽名")
        is_valid = self.verify_signature(combined_signature, message)
        if is_valid:
            print("✅ 簽名驗證成功!")
        else:
            print("❌ 簽名驗證失敗!")
        
        return is_valid


def compare_ecdsa_vs_bls():
    """比較ECDSA和BLS門檻簽名的特點"""
    print("=== ECDSA vs BLS 門檻簽名比較 ===\n")
    
    comparison = """
    特性比較:
    
    1. 簽名聚合複雜度:
       - ECDSA: 需要複雜的協議確保所有參與者使用相同的隨機數k
       - BLS: 直接使用拉格朗日插值聚合，無需協調隨機數
    
    2. 通信複雜度:
       - ECDSA: 需要多輪通信來協調隨機數生成
       - BLS: 只需一輪通信收集部分簽名
    
    3. 計算複雜度:
       - ECDSA: 相對較快的標量乘法運算
       - BLS: 需要配對運算，計算成本較高
    
    4. 簽名大小:
       - ECDSA: 約64字節 (r, s各32字節)
       - BLS: 約96字節 (G1上的點，壓縮後約48字節)
    
    5. 安全性假設:
       - ECDSA: 基於橢圓曲線離散對數問題
       - BLS: 基於雙線性Diffie-Hellman假設
    
    6. 標準化程度:
       - ECDSA: 廣泛標準化和應用
       - BLS: 相對較新，但在區塊鏈領域應用增加
    
    適用場景:
    - ECDSA: 需要與現有系統兼容，對性能要求較高
    - BLS: 門檻簽名、多重簽名場景，可以接受較高計算成本
    """
    
    print(comparison)


def main():
    """主函數 - 演示BLS門檻簽名的使用"""
    print("=== BLS門檻簽名系統演示 ===\n")
    
    # 設置參數：3-of-5 門檻簽名
    threshold = 3
    num_parties = 5
    
    # 初始化BLS門檻簽名系統
    bls_ts = BLSThresholdSignature(threshold, num_parties)
    
    # 測試消息
    message = b"Hello, BLS Threshold Signature!"
    
    # 測試場景1：足夠的簽名者
    print("\n" + "="*50)
    print("測試場景1: 3個簽名者參與 (滿足門檻)")
    signers = [1, 3, 5]
    success1 = bls_ts.simulate_signing_process(message, signers)
    
    # 測試場景2：不同的簽名者組合
    print("\n" + "="*50)
    print("測試場景2: 不同的3個簽名者參與")
    signers = [2, 4, 5]
    success2 = bls_ts.simulate_signing_process(message, signers)
    
    # 測試場景3：簽名者不足
    print("\n" + "="*50)
    print("測試場景3: 只有2個簽名者參與 (不滿足門檻)")
    signers = [1, 2]
    success3 = bls_ts.simulate_signing_process(message, signers)
    
    # 測試場景4：所有參與者都簽名
    print("\n" + "="*50)
    print("測試場景4: 所有5個參與者都簽名")
    signers = [1, 2, 3, 4, 5]
    success4 = bls_ts.simulate_signing_process(message, signers)
    
    # 總結
    print("\n" + "="*50)
    print("BLS測試總結:")
    print(f"場景1 (3個簽名者): {'✅ 成功' if success1 else '❌ 失敗'}")
    print(f"場景2 (不同3個簽名者): {'✅ 成功' if success2 else '❌ 失敗'}")
    print(f"場景3 (2個簽名者): {'✅ 成功' if success3 else '❌ 失敗'}")
    print(f"場景4 (5個簽名者): {'✅ 成功' if success4 else '❌ 失敗'}")
    
    # 比較分析
    print("\n" + "="*50)
    compare_ecdsa_vs_bls()


if __name__ == "__main__":
    main()