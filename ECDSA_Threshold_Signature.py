#!/usr/bin/env python3
"""
Threshold Signature Implementation using ECDSA and Shamir's Secret Sharing
支援 t-of-n threshold signature scheme
"""

import hashlib
import secrets
import numpy as np
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_der, sigdecode_der
from Crypto.Util.number import inverse


@dataclass
class SecretShare:
    """秘密分享的數據結構"""
    x: int  # 分享者的ID
    y: int  # 分享的值
    

@dataclass
class PartialSignature:
    """部分簽名的數據結構"""
    signer_id: int
    r: int
    s: int


class ShamirSecretSharing:
    """Shamir秘密分享方案實作"""
    
    def __init__(self, threshold: int, num_parties: int, prime: int = None):
        self.threshold = threshold
        self.num_parties = num_parties
        # 使用secp256k1的order作為質數
        self.prime = prime or SECP256k1.order
    
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
        
        return (numerator * inverse(denominator, self.prime)) % self.prime
    
    def reconstruct_secret(self, shares: List[SecretShare]) -> int:
        """從分享重建秘密"""
        if len(shares) < self.threshold:
            raise ValueError(f"需要至少 {self.threshold} 個分享來重建秘密")
        
        # 只使用前threshold個分享
        selected_shares = shares[:self.threshold]
        secret = 0
        
        for i, share in enumerate(selected_shares):
            coeff = self.lagrange_coefficient(selected_shares, i)
            secret = (secret + share.y * coeff) % self.prime
        
        return secret


class ThresholdSignature:
    """門檻簽名系統實作"""
    
    def __init__(self, threshold: int, num_parties: int):
        self.threshold = threshold
        self.num_parties = num_parties
        self.prime = SECP256k1.order
        self.sss = ShamirSecretSharing(threshold, num_parties, self.prime)
        
        # 生成主密鑰和公鑰
        self.master_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.master_key.verifying_key
        
        # 分發私鑰分享
        private_key_int = int(self.master_key.privkey.secret_multiplier)
        self.private_shares = self.sss.create_shares(private_key_int)
        
        print(f"門檻簽名系統初始化完成:")
        print(f"- 門檻值: {threshold}")
        print(f"- 參與者數量: {num_parties}")
        print(f"- 公鑰: {self.public_key.to_string().hex()}")
    
    def get_private_share(self, party_id: int) -> SecretShare:
        """獲取指定參與者的私鑰分享"""
        if party_id < 1 or party_id > self.num_parties:
            raise ValueError(f"參與者ID必須在1到{self.num_parties}之間")
        return self.private_shares[party_id - 1]
    
    def create_partial_signature(self, party_id: int, message: bytes, k: int = None) -> PartialSignature:
        """創建部分簽名"""
        private_share = self.get_private_share(party_id)
        
        # 計算消息哈希
        message_hash = hashlib.sha256(message).digest()
        hash_int = int.from_bytes(message_hash, 'big') % self.prime
        
        # 使用共同的隨機數k（在實際應用中，這需要通過安全的分布式協議生成）
        if k is None:
            k = getattr(self, '_shared_k', None)
            if k is None:
                k = secrets.randbelow(self.prime - 1) + 1
                self._shared_k = k
        
        # 計算r = (k * G).x mod n
        point = k * SECP256k1.generator
        r = point.x() % self.prime
        
        # 計算部分簽名: s_i = k^(-1) * (hash + r * x_i) mod n
        # 其中x_i是參與者i的私鑰分享
        k_inv = inverse(k, self.prime)
        s_partial = (k_inv * (hash_int + r * private_share.y)) % self.prime
        
        return PartialSignature(signer_id=party_id, r=r, s=s_partial)
    
    def combine_signatures(self, partial_sigs: List[PartialSignature], message: bytes) -> Tuple[int, int]:
        """組合部分簽名為完整簽名"""
        if len(partial_sigs) < self.threshold:
            raise ValueError(f"需要至少 {self.threshold} 個部分簽名")
        
        # 檢查所有部分簽名的r值是否相同
        r_values = [sig.r for sig in partial_sigs]
        if len(set(r_values)) != 1:
            raise ValueError("所有部分簽名的r值必須相同")
        
        r = partial_sigs[0].r
        
        # 創建用於拉格朗日插值的分享
        s_shares = []
        for sig in partial_sigs[:self.threshold]:
            s_shares.append(SecretShare(x=sig.signer_id, y=sig.s))
        
        # 使用拉格朗日插值組合s值
        s_combined = self.sss.reconstruct_secret(s_shares)
        
        return (r, s_combined)
    
    def verify_signature(self, signature: Tuple[int, int], message: bytes) -> bool:
        """驗證簽名"""
        try:
            r, s = signature
            
            if r <= 0 or r >= self.prime or s <= 0 or s >= self.prime:
                return False
            
            # 計算消息哈希
            message_hash = hashlib.sha256(message).digest()
            hash_int = int.from_bytes(message_hash, 'big') % self.prime
            
            # ECDSA驗證算法
            # 1. 計算 w = s^(-1) mod n
            w = inverse(s, self.prime)
            
            # 2. 計算 u1 = hash * w mod n
            u1 = (hash_int * w) % self.prime
            
            # 3. 計算 u2 = r * w mod n  
            u2 = (r * w) % self.prime
            
            # 4. 計算點 (x1, y1) = u1*G + u2*Q
            point1 = u1 * SECP256k1.generator
            point2 = u2 * self.public_key.pubkey.point
            result_point = point1 + point2
            
            # 5. 驗證 r ≡ x1 (mod n)
            return r == (result_point.x() % self.prime)
            
        except Exception as e:
            print(f"簽名驗證失敗: {e}")
            return False
    
    def simulate_signing_process(self, message: bytes, signers: List[int]) -> bool:
        """模擬完整的門檻簽名流程"""
        print(f"\n開始門檻簽名流程:")
        print(f"消息: {message.decode('utf-8', errors='ignore')}")
        print(f"參與簽名者: {signers}")
        
        if len(signers) < self.threshold:
            print(f"❌ 簽名者數量不足，需要至少 {self.threshold} 個")
            return False
        
        # 重置共享的k值
        if hasattr(self, '_shared_k'):
            delattr(self, '_shared_k')
        
        # 1. 創建部分簽名
        print("\n步驟1: 創建部分簽名")
        partial_signatures = []
        for signer_id in signers:
            partial_sig = self.create_partial_signature(signer_id, message)
            partial_signatures.append(partial_sig)
            print(f"  參與者 {signer_id}: r={hex(partial_sig.r)[:10]}..., s={hex(partial_sig.s)[:10]}...")
        
        # 2. 組合簽名
        print("\n步驟2: 組合部分簽名")
        try:
            combined_signature = self.combine_signatures(partial_signatures, message)
            print(f"  組合簽名: r={hex(combined_signature[0])[:10]}..., s={hex(combined_signature[1])[:10]}...")
        except Exception as e:
            print(f"❌ 簽名組合失敗: {e}")
            return False
        
        # 3. 驗證簽名
        print("\n步驟3: 驗證簽名")
        is_valid = self.verify_signature(combined_signature, message)
        if is_valid:
            print("✅ 簽名驗證成功!")
        else:
            print("❌ 簽名驗證失敗!")
        
        return is_valid


def main():
    """主函數 - 演示門檻簽名的使用"""
    print("=== 門檻簽名系統演示 ===\n")
    
    # 設置參數：3-of-5 門檻簽名
    threshold = 3
    num_parties = 5
    
    # 初始化門檻簽名系統
    ts = ThresholdSignature(threshold, num_parties)
    
    # 測試消息
    message = b"Hello, Threshold Signature!"
    
    # 測試場景1：足夠的簽名者
    print("\n" + "="*50)
    print("測試場景1: 3個簽名者參與 (滿足門檻)")
    signers = [1, 3, 5]
    success1 = ts.simulate_signing_process(message, signers)
    
    # 測試場景2：不同的簽名者組合
    print("\n" + "="*50)
    print("測試場景2: 不同的3個簽名者參與")
    signers = [2, 4, 5]
    success2 = ts.simulate_signing_process(message, signers)
    
    # 測試場景3：簽名者不足
    print("\n" + "="*50)
    print("測試場景3: 只有2個簽名者參與 (不滿足門檻)")
    signers = [1, 2]
    success3 = ts.simulate_signing_process(message, signers)
    
    # 測試場景4：所有參與者都簽名
    print("\n" + "="*50)
    print("測試場景4: 所有5個參與者都簽名")
    signers = [1, 2, 3, 4, 5]
    success4 = ts.simulate_signing_process(message, signers)
    
    # 總結
    print("\n" + "="*50)
    print("測試總結:")
    print(f"場景1 (3個簽名者): {'✅ 成功' if success1 else '❌ 失敗'}")
    print(f"場景2 (不同3個簽名者): {'✅ 成功' if success2 else '❌ 失敗'}")
    print(f"場景3 (2個簽名者): {'✅ 成功' if success3 else '❌ 失敗'}")
    print(f"場景4 (5個簽名者): {'✅ 成功' if success4 else '❌ 失敗'}")


if __name__ == "__main__":
    main()