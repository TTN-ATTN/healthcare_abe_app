# # cloud_storage/server/authorize.py
# from flask import request, jsonify
# from functools import wraps
# import jwt
# import os
# from ast import literal_eval

# # Sử dụng cùng SECRET_KEY với Trusted Authority trong môi trường thực tế
# # Trong ví dụ này, chúng ta sẽ sử dụng một key cố định
# SECRET_KEY = "secret_key"  # Trong thực tế, nên sử dụng biến môi trường

# def check_token(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         token = None
        
#         # Kiểm tra token trong header
#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization']
        
#         if not token:
#             return jsonify({'error': 'Token is missing!'}), 401
        
#         try:
#             # Giải mã token
#             data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
#             user = {
#                 'user_id': data['user_id'],
#                 'attribute': data['attribute']
#             }
#         except jwt.ExpiredSignatureError:
#             return jsonify({'error': 'Token has expired!'}), 401
#         except jwt.InvalidTokenError:
#             return jsonify({'error': 'Invalid token!'}), 401
        
#         # Truyền thông tin người dùng vào hàm được trang trí
#         return f(user, *args, **kwargs)
    
#     return decorated


# cloud_storage/server/authorize.py
from flask import request, jsonify
from functools import wraps
import jwt
import os
from ast import literal_eval

# Sử dụng cùng SECRET_KEY với Trusted Authority trong môi trường thực tế
# Trong ví dụ này, chúng ta sẽ sử dụng một key cố định
SECRET_KEY = "your_secret_key_here"  # Trong thực tế, nên sử dụng biến môi trường

def check_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Kiểm tra token trong header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        
        if not token:
            return jsonify({'error': 'Token is missing!'}), 401
        
        try:
            # Giải mã token
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user = {
                'user_id': data['user_id'],
                'attribute': data['attribute']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401
        
        # Truyền thông tin người dùng vào hàm được trang trí
        return f(user, *args, **kwargs)
    
    return decorated