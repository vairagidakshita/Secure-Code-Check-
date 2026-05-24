# Intentionally unsafe test script
   api_key = "AIzaSyD-fake-key-value-12345"
   
   def execute_user_command(user_input):
       import os
       # Vulnerable to command injection
       os.system("ping " + user_input)
       
       # Weak hashing algorithm
       import hashlib
       hashed_data = hashlib.md5(b"password123")