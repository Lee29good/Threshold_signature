# 這邊比較像 multi-signature 的設計方式：用每個人個別的私鑰去sign，再驗證時使用個別的公鑰去驗證
from ecdsa import SigningKey, SECP256k1
import hashlib

# 建立三個私鑰與公鑰對
keys = [SigningKey.generate(curve=SECP256k1) for _ in range(3)]
pubkeys = [k.verifying_key for k in keys]

# 模擬錢包地址：取三個公鑰 hash 串接後再做一次 hash（簡化版）
wallet_id = hashlib.sha256(b''.join([pk.to_string() for pk in pubkeys])).hexdigest()
print(f"🔐 模擬多簽錢包地址: {wallet_id}")

# 要簽署的交易內容
transaction = b"Send 10 BTC to Alice"

# 任選兩個簽名
signatures = [keys[0].sign(transaction), keys[1].sign(transaction)]

# 驗證簽名（模擬 2-of-3）
verified = (
    pubkeys[0].verify(signatures[0], transaction) and
    pubkeys[1].verify(signatures[1], transaction)
)

print(f"✅ 交易是否被授權（2-of-3）: {verified}")