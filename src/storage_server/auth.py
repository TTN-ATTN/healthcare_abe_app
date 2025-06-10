from functools import wraps
from traceback import print_exc
import jwt
from flask import request

def check_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "Authorization" in request.headers:
            token = request.headers["Authorization"]

        if not token:
            return {"message": "Authentication Token is missing!", "data": None, "error": "Unauthorized"}, 401

        try:
            with open('./certs/jwtkey_pub.pem', 'rb') as file:
                key = file.read()
                user = jwt.decode(token, key, algorithms="EdDSA")
        except Exception:
            print_exc()
            return {"message": "Something went wrong", "data": None}, 500

        return f(user, *args, **kwargs)

    return decorated