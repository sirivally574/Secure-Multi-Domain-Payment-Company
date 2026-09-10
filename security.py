import re
from werkzeug.security import generate_password_hash, check_password_hash


def validate_username(username):
    if not username:
        return False, "Username is required."

    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."

    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return False, "Username can contain only letters, numbers and underscores."

    return True, ""


def validate_password(password):
    if not password:
        return False, "Password is required."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    if len(password) > 64:
        return False, "Password must not exceed 64 characters."

    if not re.search(r"[A-Z]", password):
        return False, "Password needs an uppercase letter."

    if not re.search(r"[a-z]", password):
        return False, "Password needs a lowercase letter."

    if not re.search(r"\d", password):
        return False, "Password needs a number."

    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password needs a special character."

    return True, ""


def hash_password(password):
    return generate_password_hash(password)


def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)


def validate_amount(amount):
    try:
        value = float(amount)
    except (TypeError, ValueError):
        return False, "Enter a valid payment amount."

    if value <= 0:
        return False, "Payment amount must be greater than zero."

    if value > 100000:
        return False, "Demo payment limit is ₹100,000."

    return True, value