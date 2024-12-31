# Messenger App

This project is a secure messaging application that combines frontend design and backend cryptographic functionalities to ensure secure communication. Developed as a part of a Cybersecurity-focused project, the app demonstrates skills in secure data handling, encryption, and full-stack development.

## Features

- User Authentication: Secure login and signup with hashed passwords using `bcrypt`.
- End-to-End Encryption: Messages are encrypted and decrypted using cryptographic algorithms.
- Frontend Design: Responsive and user-friendly interface using HTML, CSS, and JavaScript.
- Database Integration: SQLite database for storing user and message data.
- API Endpoints: Flask-powered backend with APIs for secure data exchange.

## Key Technologies and Skills

### Backend
- Flask Framework: Built a robust backend to handle requests, user sessions, and data routing.
- Database Management: Used SQLite for secure storage of user data and messages.
- Cryptography: Implemented RSA for key pair generation and AES for symmetric encryption of messages. Key functionalities:
  - Key Management: RSA private-public key pairs for encrypting and decrypting messages.
  - Message Encryption: AES for encrypting message bodies to ensure data confidentiality.
  - Password Security: `bcrypt` for hashing user passwords.

### Frontend
- Responsive Design: HTML templates and CSS styles for a clean, user-friendly interface.
- JavaScript: Implemented message decryption logic with `Forge` for seamless user experience.

## Setup and Installation

1. Clone the Repository:
   ```bash
   git clone https://github.com/luwke1/messenger-app.git
   cd messenger-app
   ```

2. Install Dependencies:
   Use the provided `requirements.txt` file to install Python dependencies.
   ```bash
   pip install -r requirements.txt
   ```

3. Set Up the Database:
   Run the `setupdb.py` script to initialize the SQLite database.
   ```bash
   python setupdb.py
   ```

4. Run the Application:
   Launch the Flask application.
   ```bash
   python app.py
   ```

5. Access the App:
   Open your browser and navigate to `http://127.0.0.1:5000`.

## Cryptographic Implementation

### Backend Encryption
- RSA: Public and private key pairs are generated for users using the `Crypto.PublicKey` library.
- AES: Messages are encrypted with AES (Advanced Encryption Standard) for performance and security.
- Key Derivation: Used `PBKDF2` for secure key generation from user input.

### Frontend Decryption
- Implemented message decryption in the browser using JavaScript and the `Forge` library to securely process messages.
