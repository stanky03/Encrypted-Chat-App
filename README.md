# Encrypted-Chat-App  
Basic Encrypted Chat App Implementation

# Overview

This project is a command-line based encrypted chat application written in Python. It allows two users to communicate securely using symmetric AES encryption, with asymmetric RSA/ECC key exchange and digital signatures. The system also demonstrates common attack simulations such as Man-in-the-Middle (MITM) and replay attacks with basic defenses like timestamp verification. The project was designed for educational purposes (to explore practical cryptography and secure communication protocols in a controlled environment).

# Features

- Encrypted messaging using AES (EAX mode)
- RSA and ECC key generation for secure key exchange
- Ed25519 digital signatures for message integrity
- bcrypt password hashing for secure authentication
- MITM attack simulation via proxy with key substitution
- Replay attack demonstration with captured messages
- Timestamp-based replay detection
- Modular cryptographic helper functions

# Prerequisites
pip install cryptography pycryptodome bcrypt pwinput
