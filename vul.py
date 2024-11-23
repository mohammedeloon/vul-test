import os
import subprocess
import pickle
import hashlib
import random
import jwt

# Vulnerability 1: Hardcoded Secret Key (Sensitive Data Exposure)
SECRET_KEY = "my_hardcoded_secret_key"  # Sensitive key hardcoded

# Vulnerability 2: Use of `eval` (Arbitrary Code Execution)
def unsafe_eval(user_input):
    return eval(user_input)  # Executes arbitrary code

# Vulnerability 3: Command Injection
def unsafe_command(user_input):
    command = f"ping -c 4 {user_input}"  # User input passed unsanitized
    os.system(command)

# Vulnerability 4: Insecure Deserialization (Pickle)
def unsafe_pickle_load(filename):
    with open(filename, 'rb') as file:
        return pickle.load(file)  # Deserializing untrusted input

# Vulnerability 5: Weak Hash Algorithm (MD5)
def hash_password_weak(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is cryptographically broken

# Vulnerability 6: Weak Random Number Generator (Predictable RNG)
def generate_token():
    return random.random()  # Not cryptographically secure

# Vulnerability 7: Overly Permissive File Permissions
def create_temp_file():
    filename = "temp_file.txt"
    with open(filename, 'w') as file:
        file.write("Temporary data")
    os.chmod(filename, 0o777)  # Insecure permissions

# Vulnerability 8: Use of JWT with Hardcoded Secret Key
def create_jwt():
    payload = {"user": "admin"}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')  # Hardcoded key used

# Vulnerability 9: SQL Injection (Unsanitized User Input in SQL Query)
def execute_sql(user_input):
    query = f"SELECT * FROM users WHERE username = '{user_input}';"  # Vulnerable query
    print("Executing query:", query)
    # Simulate database execution here (e.g., cursor.execute(query))


def check_value(value):
    assert value > 0, "Value must be positive"  
    print("Value is valid")
