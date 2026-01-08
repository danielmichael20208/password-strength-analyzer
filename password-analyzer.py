import re
import math

COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein"]

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[!@#$%^&*()_+]", password): charset += 12
    return len(password) * math.log2(charset) if charset else 0

def analyze(password):
    issues = []
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This password is extremely common and unsafe.")
    if len(password) < 8:
        issues.append("Password is too short (minimum 8 characters).")
    if not re.search(r"[A-Z]", password):
        issues.append("Add uppercase letters.")
    if not re.search(r"[0-9]", password):
        issues.append("Add numbers.")
    if not re.search(r"[!@#$%^&*()_+]", password):
        issues.append("Add special characters.")
    entropy = calculate_entropy(password)
    return issues, round(entropy, 2)

if __name__ == "__main__":
    pwd = input("Enter a password to analyze: ")
    issues, entropy = analyze(pwd)

    print("\nPassword Security Report")
    print("-" * 25)
    print(f"Entropy Score: {entropy}")
    if issues:
        for i in issues:
            print("⚠", i)
    else:
        print("✅ Strong password!")
