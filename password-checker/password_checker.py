"""
Password Strength Checker
Analyzes passsword strength and gives detailed feedback.
"""
import re 
import math
import json

COMMON_PASSWORDS = {
    "12345678" ,
    "123456789" ,
    "12345679" ,
    "12345789" ,
    "11111111" ,
    "admin123" ,
    "123admin" ,
    "hello123" ,
    "welcome1234" ,
    "987654321" ,
    "87654321" ,
    "1q2w3e4r" ,
}


def calculate_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def check_strength(password):
    """
    Analyze password and return a detailed report.
    Returns a dict with score (0-100), label, entropy, and suggestions.
    """
    if not password:
        return {"error": "Password cannot be empty"}

    score = 0
    issues = []
    tips = []

    # --- Length ---
    length = len(password)
    if length < 6:
        issues.append("Too short (minimum 6 characters)")
    elif length < 8:
        score += 10
        tips.append("Use at least 8 character for better security")
    elif length < 12:
        score += 20
        tips.append("12+ characters is ideal")
    elif length < 16:
        score += 30
    else:
        score += 40


    # --- Character variety ---
    has_lower  = bool(re.search(r'[a-z]', password))
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_digit  = bool(re.search(r'[0-9]', password))
    has_symbol  = bool(re.search(r'[^a-zA-Z0-9]', password))

    variety = sum([has_lower, has_upper , has_digit , has_symbol])
    score += variety * 10

    if not has_upper:  tips.append("Add uppercase letters (A-Z)")
    if not has_lower:  tips.append("Add lowercase letters (a-z)")
    if not has_digit:  tips.append("Add numbers (0-9)")
    if not has_symbol:  tips.append("Add symbols (!@#$%^&*)")

    # --- Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        score = max(0, score - 40)
        issues.append("This is a very common password - avoid it!")


    # --- Repeated characters ---
    if re.search(r'(.)\1{2,}', password):
        score = max(0, score - 10)
        issues.append("Avoid repeating characters (e.g. 'aaa' , '111')") 


    # --- Sequential patterns ---
    sequences = ["abcdef", "qwerty", "123456", "654321"]
    for seq in sequences:
        if seq in password.lower():
            score = max(0, score - 10)
            issues.append(f"Avoid keyboard/number sequences like  '{seq}'")
            break


    score = max(0, min(score, 100))

    # --- Label ---
    if score < 20:   label = "Very Weak"
    elif score < 40: label = "Weak"
    elif score < 60: label = "Fair"
    elif score < 80: label = "Strong"
    else:            label = "Very Strong"

    entropy = calculate_entropy(password)

    return {
       "password_length": length,
       "score": score,
       "label": label,
       "entropy_bits": entropy,
       "has_lowercase": has_lower,
       "has_uppercase": has_upper,
       "has_digits": has_digit,
       "has_symbols": has_symbol,
       "issues": issues,
       "tips": tips
    }

if __name__ == "__main__":
    import sys
    pwd = sys.argv[1] if len(sys.argv) > 1 else "MyP@ssw0rd!"
    result = check_strength(pwd)
    print(json.dumps(result, indent=2))


