from flask import request, jsonify, abort, session, redirect, url_for,make_response
from .services.book_service import *
from .models import *
import hashlib
import secrets

import jwt
from datetime import datetime, timedelta

import os
from werkzeug.utils import secure_filename



from joblib import load
        
import pickle
import pandas as pd  


import json
from huggingface_hub import InferenceClient
# from langchain.prompts import PromptTemplate 

# Secret key for encoding JWTs
SECRET_KEY = 'your_secret_key_here'  # Replace with your actual secret key



def generate_jwt(username):
    expiration = datetime.utcnow() + timedelta(hours=1)
    token = jwt.encode({'username': username, 'exp': expiration}, SECRET_KEY, algorithm='HS256')
    print("token",token)
    return token

# Function to generate a salted and hashed password
def hash_password(password, salt):
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed_password

def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return func(*args, **kwargs)
    wrapper.__name__ = f'login_required_{func.__name__}'
    return wrapper


def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        stored_salt = user.salt
        stored_hashed_password = user.password
        hashed_password = hash_password(password, stored_salt)
        if hashed_password == stored_hashed_password:
            return True
    return False

def register_routes(app):
    @app.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if authenticate(username, password):
            token = generate_jwt(username)
            print("token login",token)
            response_data = {
                'message': 'Login successful',
                'token': token  
            }
            return jsonify(response_data)

        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    @app.route('/register', methods=['POST'])
    def register():
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        print(username)
        print(password)
        if not username or not password:
            print('1')
            return jsonify({'message': 'Username and password are required'}), 400
            
        if User.query.filter_by(username=username).first():
            print('2')
            return jsonify({'message': 'Username already exists'}), 400
        # Generate a random salt
        salt = secrets.token_hex(16)

        # Hash the password with the salt
        hashed_password = hash_password(password, salt)
        print(hashed_password)

        # Create a new user with the hashed password and salt
        new_user = User(username=username, password=hashed_password, salt=salt)
        
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201

    @app.route('/books', methods=['GET', 'POST'])
    def manage_books():
        token_ = request.headers.get('Authorization')
        token = token_.split(' ')[1]
        if token is None:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        if request.method == 'GET':
            user = User.query.filter_by(username=username).first()
            if user:

                public_books = Book.query.filter_by(public=True).all()

                books_list = []

                for book in public_books:
                    books_list.append({
                        'id': book.id,
                        'title': book.title,
                        'author_name': book.author_name,
                        'published_date': book.published_date,
                        'isbn': book.isbn,
                        'public': book.public
                    })

                return jsonify(books_list)
            return jsonify({'message': 'User not found'}), 404

        elif request.method == 'POST':
            print(username)
            data = request.get_json()
            user = User.query.filter_by(username=username).first()
            if user:
                public = data.get('public', False)
                new_book = Book(
                    title=data.get('title'),
                    author_name=data.get('author_name'),
                    user_id=user.id,
                    published_date=data.get('published_date'),
                    isbn=data.get('isbn'),
                    public=public
                )
                db.session.add(new_book)
                db.session.commit()
                return jsonify({
                    'id': new_book.id,
                    'title': new_book.title,
                    'author_name': new_book.author_name,
                    'user_id': new_book.user_id,
                    'published_date': new_book.published_date.strftime('%Y-%m-%d') if new_book.published_date else None,
                    'isbn': new_book.isbn,
                    'public': new_book.public
                }), 201

    @app.route('/books/<int:book_id>', methods=['GET', 'PUT', 'DELETE'])
    def manage_book(book_id):
        token_ = request.headers.get('Authorization')
        token = token_.split(' ')[1]
        if token is None:
            return jsonify({'message': 'Token is missing'}), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404       #changes.........................
        
         
        if request.method == 'GET':
            book = Book.query.filter_by(id=book_id, public=True).first()
            if book:
                
                if book.user_id == user.id:
                    
                    return jsonify({
                        'id': book.id,
                        'title': book.title,
                        'author': book.author_name,
                        'published_date': book.published_date.strftime('%Y-%m-%d') if book.published_date else None,
                        'isbn': book.isbn,
                        'public': book.public,
                        'editable': True  # Indicate that the book is editable by the current user
                    })
                else:
                    
                    return jsonify({
                        'id': book.id,
                        'title': book.title,
                        'author': book.author_name,
                        'published_date': book.published_date.strftime('%Y-%m-%d') if book.published_date else None,
                        'isbn': book.isbn,
                        'public': book.public
                    })
            else:
                return jsonify({'message': 'Book not found'}), 404

        elif request.method == 'PUT':
            data = request.get_json()
            book = Book.query.filter_by(id=book_id).first()
            if book:
                book.title = data.get('title', book.title)
                book.author= data.get('author', book.author_name)      # changes
                book.published_date = data.get('published_date', book.published_date)
                book.isbn = data.get('isbn', book.isbn)
                book.public = data.get('public', book.public)
                db.session.commit()
                return jsonify({
                    'id': book.id,
                    'title': book.title,
                    'author': book.author_name,
                    'published_date': book.published_date.strftime('%Y-%m-%d') if book.published_date else None,
                    'isbn': book.isbn,
                    'public': book.public
                })
            return jsonify({'message': 'Book not found'}), 404

        elif request.method == 'DELETE':
            book = Book.query.get(book_id)
            if book:
                db.session.delete(book)
                db.session.commit()
                return '', 204
            return jsonify({'message': 'Book not found'}), 404

    @app.route('/logout', methods=['POST'])
    def logout():
        auth_header = request.headers.get('Authorization')
        if auth_header:  
            response = make_response(jsonify({'message': 'Logout successful'}))
            response.set_cookie('session_token', '', expires=0)
            return response
        else:
            return jsonify({'message': 'Authorization header missing'}), 401


    @app.route('/profile', methods=['GET'])
    def profile():
        token_ = request.headers.get('Authorization')
        token = token_.split(' ')[1]
        if token is None:
            return jsonify({'message': 'Token is missing'}), 401
        print('hi',token_)
        try:
            print('this is token',token_)
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        user = User.query.filter_by(username=username).first()
        if user:
            # user_books = Book.query.filter_by(user_id=user.id).all()   #old logic
            
            user_books = Book.query.filter((Book.user_id == user.id) & (Book.public == 0)).all()

            books_list = []

            for book in user_books:
                books_list.append({
                    'id': book.id,
                    'author_name': book.author_name,
                    'title': book.title,
                    'published_date': book.published_date,
                    'isbn': book.isbn,
                    'public': book.public
                })
                
                
            profile_pic_filename = os.path.basename(user.pic) 

            profile_pic_url = url_for('static', filename=f'uploads/profile_pics/{profile_pic_filename}', _external=True)

            user_data = {
                'username': user.username,
                'profilePicUrl': profile_pic_url,
                'books': books_list
            }

            return jsonify(user_data)
        return jsonify({'message': 'User not found'}), 404
    
    
    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}
               
               
    @app.route('/upload-profile-pic', methods=['POST'])
    def upload_profile_pic():
        token_ = request.headers.get('Authorization')
        if token_ is None:
            return jsonify({'message': 'Token is missing'}), 401

        token = token_.split(' ')[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401

        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({'message': 'User not found'}), 404

        if 'profilePic' not in request.files:
            return jsonify({'message': 'No file part in the request'}), 400

        file = request.files['profilePic']
        if file.filename == '':
            return jsonify({'message': 'No selected file'}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            user.pic = file_path
            print(file_path)
            db.session.commit()
            
            # Generate a URL for the profile picture
            profile_pic_url = url_for('static', filename=f'uploads/profile_pics/{filename}', _external=True)
    

            db.session.commit()

            return jsonify({'profilePicUrl': profile_pic_url}), 200

        return jsonify({'message': 'File type not allowed'}), 400
    



###############################         machine laerning           #######################    
 
    with open(r'D:\utkal_labs\weather_predict\linear_regression_model.pkl', 'rb') as file:
        model = pickle.load(file)   
    
   
    @app.route('/predict-weather', methods=['POST'])
    def predict_weather():
        token_ = request.headers.get('Authorization')
        if token_ is None:
            return jsonify({'message': 'Token is missing'}), 401

        token = token_.split(' ')[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        try:
            data = request.get_json()
            date_str = data.get('date')
            if not date_str:
                return jsonify({"error": "Date is required."}), 400
            # Convert the date string to datetime object and then to ordinal
            date = datetime.strptime(date_str, '%Y-%m-%d')
            date_ordinal = date.toordinal()
            # Create a DataFrame with the correct feature name
            features = pd.DataFrame([[date_ordinal]], columns=['date_ordinal'])
            prediction = model.predict(features)
            return jsonify({'prediction': prediction[0]}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        
        
        
########################################

    loaded_model = load(r'D:\utkal_labs\machine_learning\price_model2.joblib')

    # Encoded data mappings
    encoded_data = {
        "RAM": {"2GB": 16,"3GB":20, "4GB": 25, "6GB": 31, "8GB":36,"12GB":8,"256GB":13},
        "ROM/Storage": {"32GB": 14, "64GB": 20, "128GB": 5,"256GB":13},
        "Back/Rare Camera": {
            "8MP Dual Camera": 171, "50MP+2MP": 118, "8MP Dual Rear Camera": 172,
            "50MP Dual Rear Camera": 137, "48MP + 2MP + 2MP + AI Lens Camera": 87,
            "48MP + 8MP + 2MP + AI Lens Camera": 95, "16MP + 5MP + 2MP + Low Light Sensor": 62,"50MP + 2MP Depth Sensor + 2MP Macro Sensor":123,"64MP + 8MP + 2MP":154,"48MP + 8MP + 2MP":93,"50MP + 8MP":133,"64MP + 8MP + 2MP":154,"108MP + 8MP + 2MP":21,"64MP (OIS) + 8MP + 2MP":143,"13MP + 2MP + 2MP":43
        },
        "Front Camera": {"5MP": 26, "8MP": 32, "16MP": 12, "16MP+8MP": 10, "32MP": 20,"13MP Front Camera":8,"16MP Front Camera":12,"8MP Front Camera":32},
        "Battery": {"5000 mAh": 78, "4500mAh": 64, "4000mAh": 45},
        "Processor": {
            "Mediatek Helio A22": 187, "Mediatek Dimensity 700": 173, "Helio G36": 106,
            "Mediatek Helio G85 Processor": 193, "MediaTek Helio G70": 144, "MediaTek Helio G90T": 149,
            "Helio P22 (MTK6762)": 109,"Mediatek Helio G99":197,"Mediatek Helio G96":195,"Qualcomm Snapdragon 695 Processor":153,"Mediatek Dimensity 810 Processor":177,"Qualcomm Snapdragon 778G Processor":195,"Qualcomm Snapdragon 695 Processor":264,"Qualcomm Snapdragon 695 Processor":253,"MediaTek Dimensity 700 Processor":134,"Qualcomm Snapdragon 695 5G Processor":252,"Qualcomm Snapdragon 7+ Gen 2 (4nm) Processor":254,"Qualcomm Snapdragon 695 Processor":253,"MediaTek Helio G35 Processor":143
        }
    }

    # @app.route('/predict-price', methods=['POST'])
    # def predict_price():
    #     token_ = request.headers.get('Authorization')
    #     if token_ is None:
    #         return jsonify({'message': 'Token is missing'}), 401

    #     token = token_.split(' ')[1]
        

    #     try:
    #         payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    #         username = payload['username']
    #     except jwt.ExpiredSignatureError:
    #         return jsonify({'message': 'Token has expired'}), 401
    #     except jwt.InvalidTokenError:
    #         return jsonify({'message': 'Invalid token'}), 401
        
    #     user = User.query.filter_by(username=username).first()
    #     if user is None:
    #         return jsonify({'message': 'User not found'}), 404
        
        
        
    #     try:
    #         user_input = request.json
    #         encoded_input = {feature: encoded_data[feature][user_input[feature]] for feature in encoded_data}
    #         input_df = pd.DataFrame([encoded_input])
    #         prediction = loaded_model.predict(input_df)
    #         return jsonify({'predicted_value': prediction[0]}), 200
    #     except KeyError as e:
    #         return jsonify({'error': f'Invalid value: {str(e)}'}), 400
    #     except Exception as e:
    #         return jsonify({'error': f'Error: {str(e)}'}), 500
        
        
        
    @app.route('/predict-price', methods=['POST'])
    def predict_price():
        token_ = request.headers.get('Authorization')
        if token_ is None:
            return jsonify({'message': 'Token is missing'}), 401

        token = token_.split(' ')[1]
        

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        
        
        try:
            user_input = request.json
            encoded_input = {feature: encoded_data[feature][user_input[feature]] for feature in encoded_data}
            input_df = pd.DataFrame([encoded_input])
            prediction = loaded_model.predict(input_df)
            return jsonify({'predicted_value': prediction[0]}), 200
        except KeyError as e:
            return jsonify({'error': f'Invalid value: {str(e)}'}), 400
        except Exception as e:
            return jsonify({'error': f'Error: {str(e)}'}), 500
        
        

    @app.route('/chat-bot',methods=['POST'])
    def chatbot():

        token_ = request.headers.get('Authorization')
        if token_ is None:
            return jsonify({'message': 'Token is missing'}), 401

        token = token_.split(' ')[1]
        

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        user = User.query.filter_by(username=username).first()
        if user is None:
            return jsonify({'message': 'User not found'}), 404
        
        



        # Get JSON data from request body
        data = request.get_json()

        # Extract input text from JSON data
        user_input = data.get('input')

        # Check if input text is missing
        if not user_input:
            return jsonify({'message': 'Input text is missing'}), 400

        # Hugging Face API credentials (replace with your actual credentials)
        hf_api_token = "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"
        repo_id = "mistralai/Mistral-7B-Instruct-v0.3"

        # Initialize Hugging Face InferenceClient
        llm_client = InferenceClient(model=repo_id, token=hf_api_token, timeout=600)

        # Function to generate response from chatbot
        def generate_response(input_text):
            prompt = input_text  # Assuming the input text is directly the prompt
            response = llm_client.post(
                json={
                    "inputs": prompt,
                    "parameters": {"max_new_tokens": 200},
                    "task": "text-generation",
                }
            )
            response_dict = json.loads(response)
            return response_dict[0]["generated_text"]

            # Generate response from chatbot based on user input
        response_text = generate_response(user_input)

            # Return JSON response with bot's generated text
        return jsonify({'response': response_text})



