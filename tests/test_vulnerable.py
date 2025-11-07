# Test file with intentional security vulnerabilities for testing static_scan.py

import os
import subprocess
import pickle

# Vulnerability 1: Use of input() function
user_input = input("Enter something: ")

# Vulnerability 2: Use of eval()
result = eval(user_input)

# Vulnerability 3: SQL injection potential
query = "SELECT * FROM users WHERE name = '" + user_input + "'"

# Vulnerability 4: Command injection potential
os.system("echo " + user_input)

# Vulnerability 5: Insecure deserialization
data = pickle.loads(user_input.encode())

# Vulnerability 6: Use of shell=True
subprocess.run(user_input, shell=True)

# Vulnerability 7: Hardcoded password
password = "admin123"

print("This is a test file with security vulnerabilities")