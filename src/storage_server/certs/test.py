import jwt

with open('jwtkey_private.pem', 'rb') as f:
    private_key = f.read()

payload = {
    "sub": "user123",
    "role": "doctor"
}

token = jwt.encode(payload, private_key, algorithm="EdDSA")

print("Generated JWT:")
print(token)
