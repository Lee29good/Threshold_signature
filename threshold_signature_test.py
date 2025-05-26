from ecdsa import SigningKey, SECP256k1, VerifyingKey
from secretsharing import PlaintextToHexSecretSharer

# Step 1: 產生 ECDSA 私鑰與公鑰
sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key

# 原始私鑰 (十六進位字串)
secret_hex = sk.to_string().hex()
print(f"🔐 原始私鑰: {secret_hex}")

# Step 2: 分割秘密 (t-of-n)
threshold = 3
num_shares = 5
shares = PlaintextToHexSecretSharer.split_secret(secret_hex, threshold, num_shares)
print("\n🧩 分割後的 shares:")
for i, share in enumerate(shares):
    print(f"Share {i+1}: {share}")

# ✅ 成功案例：用足夠的 shares 重建
subset_success = shares[:threshold]  # 取前三個 share
print(f"\n✅ 嘗試用 {threshold} 個 shares 重建...")
recovered_secret_hex = PlaintextToHexSecretSharer.recover_secret(subset_success)
print(f"🔁 重建出的私鑰: {recovered_secret_hex}")
recovered_sk = SigningKey.from_string(bytes.fromhex(recovered_secret_hex), curve=SECP256k1)
message = b"hello threshold signature!"
signature = recovered_sk.sign(message)
is_valid = vk.verify(signature, message)
print(f"📝 簽章: {signature.hex()}")
print(f"✅ 驗證結果: {is_valid}")

# ❌ 失敗案例：用不足的 shares 重建（只有一個）
subset_fail = [shares[2]]  # 只給一個 share
print(f"\n❌ 嘗試只用 1 個 share 重建...")
try:
    recovered_secret_hex_fail = PlaintextToHexSecretSharer.recover_secret(subset_fail)
    print(f"⚠️ 不該成功！重建出的私鑰: {recovered_secret_hex_fail}")
    # 嘗試使用失敗的私鑰簽名
    recovered_sk_fail = SigningKey.from_string(bytes.fromhex(recovered_secret_hex_fail), curve=SECP256k1)
    signature_fail = recovered_sk_fail.sign(message)
    is_valid_fail = vk.verify(signature_fail, message)
    print(f"❌ 驗證結果: {is_valid_fail}")
except Exception as e:
    print(f"🚫 重建失敗，如預期。錯誤訊息: {e}")