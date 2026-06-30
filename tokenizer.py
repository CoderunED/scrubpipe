import hmac
import hashlib
SECRET_KEY = b"my-test-key-12345"
def tokenize(value: str) -> str:
    digest= hmac.new(SECRET_KEY,value.encode("UTF 8"),hashlib.sha256).hexdigest()
    return "TOKEN_" + digest[:8]
print(tokenize("alice@example.com"))
print(tokenize("alice@example.com"))
print(tokenize("bob@example.com"))