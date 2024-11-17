# app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sqlite3
import os
import base64

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generate a secret key

DATABASE = 'messaging.db'

# Function to get a database connection
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Enable accessing columns by name
    return conn

# Function to derive a symmetric key from the password
def derive_key(password, salt):
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    return key

# Function to encrypt the private key
def encrypt_private_key(private_key, password):
    salt = get_random_bytes(16)  # Generate a random salt
    key = derive_key(password, salt)  # Derive a symmetric key
    cipher = AES.new(key, AES.MODE_CBC)  # Initialize cipher in CBC mode
    ct_bytes = cipher.encrypt(pad(private_key, AES.block_size))  # Encrypt and pad the private key
    return salt + cipher.iv + ct_bytes  # Concatenate salt, IV, and ciphertext

# Function to decrypt the private key
def decrypt_private_key(encrypted_private_key, password):
    """
    Decrypt the private key using AES decryption with a key derived from the password.
    Expects encrypted_private_key to be concatenation of salt + iv + ciphertext.
    """
    if isinstance(encrypted_private_key, str):
        # If encrypted_private_key is a string, convert it to bytes
        # Assuming it's stored as a hex string or base64, adjust accordingly
        encrypted_private_key = bytes.fromhex(encrypted_private_key)
    
    salt = encrypted_private_key[:16]  # Extract salt (16 bytes)
    iv = encrypted_private_key[16:32]  # Extract IV (16 bytes)
    ct = encrypted_private_key[32:]    # Extract ciphertext
    
    key = derive_key(password, salt)  # Derive the symmetric key using PBKDF2
    
    # Initialize cipher with key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad the private key
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    
    return pt  # Return decrypted private key

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get username and password from the sign up form
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Hash the password with bcrypt
        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        # Generate RSA key pair for message decryption later
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Encrypt the private key with the user's password
        private_key_encrypted = encrypt_private_key(private_key, password)

        # Insert the new user into the database
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, password_hash, public_key, private_key_encrypted)
                VALUES (?, ?, ?, ?)
            """, (username, hashed.decode('utf-8'), public_key.decode('utf-8'), private_key_encrypted))
            conn.commit()
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
        finally:
            conn.close()

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get username and password from the form
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        # Retrieve user from the database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # 'password_hash' and 'private_key_encrypted' are stored as strings in the DB
            stored_password_hash = user['password_hash'].encode('utf-8')  # Convert to bytes
            stored_private_key_encrypted = user['private_key_encrypted']

            # Check password
            if bcrypt.checkpw(password, stored_password_hash):
                # Successful login
                session['user_id'] = user['id']
                session['username'] = user['username']

                # Decrypt the user's private key
                decrypted_private_key = decrypt_private_key(stored_private_key_encrypted, password)

                # Encode the decrypted private key in base64 to send to client
                decrypted_private_key_b64 = base64.b64encode(decrypted_private_key).decode('utf-8')

                # Store the decrypted private key in the session
                session['private_key'] = decrypted_private_key_b64

                flash('Logged in successfully!')
                return redirect(url_for('inbox'))
            else:
                flash('Invalid username or password.')
        else:
            flash('Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear the user session
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/inbox')
def inbox():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Fetch encrypted messages for the logged-in user
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT messages.id, messages.message_encrypted, users.username AS sender_username
        FROM messages
        JOIN users ON messages.sender_id = users.id
        WHERE messages.receiver_id = ?
    """, (session['user_id'],))
    messages = cursor.fetchall()
    conn.close()
    
    messages_list = [dict(message) for message in messages]
    print(messages_list)

    return render_template('inbox.html', messages=messages)

@app.route('/send_message', methods=['GET', 'POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get recipient username and message
        receiver_username = request.form['to_username']
        message = request.form['message']

        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve receiver's information
        cursor.execute("SELECT * FROM users WHERE username = ?", (receiver_username,))
        receiver = cursor.fetchone()

        if receiver:
            # Encrypt the message using the receiver's public key
            public_key = RSA.import_key(receiver['public_key'].encode('utf-8'))
            cipher = PKCS1_OAEP.new(public_key)
            message_encrypted = cipher.encrypt(message.encode('utf-8'))

            # Store the encrypted message in the database as hex
            cursor.execute("""
                INSERT INTO messages (sender_id, receiver_id, message_encrypted)
                VALUES (?, ?, ?)
            """, (session['user_id'], receiver['id'], message_encrypted.hex()))
            conn.commit()
            flash('Message sent successfully!')
            conn.close()
            return redirect(url_for('inbox'))
        else:
            flash('Recipient username not found.')
            conn.close()

    return render_template('send_message.html')

@app.route('/get_private_key', methods=['GET'])
def get_private_key():
    """
    Route to provide the decrypted private key to the client-side JavaScript.
    This should only be accessible if the user is logged in.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized access.'}), 401

    private_key_b64 = session.get('private_key')
    if not private_key_b64:
        return jsonify({'error': 'Private key not found.'}), 404

    return jsonify({'private_key': private_key_b64})

if __name__ == '__main__':
    app.run(debug=True)
