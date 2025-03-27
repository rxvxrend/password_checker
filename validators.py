import re
from os import path
from password_check_api import check_password_online

def check_password_patterns(password):
    patterns = {
        'Повторяющиеся символы': r'(.)\1{2,}',
        'Последовательности цифр': r'0123|1234|2345|3456|4567|5678|6789|7890',
        'Последовательности букв': r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz',
        'Часто используемые шаблоны': r'(?i)password|admin|qwerty',
        'Только цифры': r'^\d+$',
        'Только буквы': r'^[a-zA-Z]+$',
        'Повторяющиеся последовательности': r'^(.*?)\1+$'
    }
    
    for name, pattern in patterns.items():
        if re.search(pattern, password):
            return -1
    return 0

def load_common_passwords(filepath):
    filepath = path.join(path.dirname(__file__), filepath)
    with open(filepath) as file:
        return set(line.strip() for line in file)

common_passwords = load_common_passwords("10k-most-common.txt")

def check_common_password(password):
    return password in common_passwords

def validate_uppercase(password):
    return any(char.isupper() for char in password)

def validate_digits(password):
    return any(char.isdigit() for char in password)

def validate_special_char(password):
    return any(char in '!@#$%^&*' for char in password)


def analyze_password(password):
    
    if check_common_password(password):
        return '❌ Этот пароль слишком распространён! Выберите другой.'

    if len(password) > 64:
        return 'Пароль слишком длинный.'

    breach_penalty, breach_feedback = check_password_online(password)

    score = sum([
        len(password) >= 8,
        len(password) >= 12,
        validate_uppercase(password),
        validate_digits(password),
        validate_special_char(password)
    ]) + breach_penalty + check_password_patterns(password)

    if score <= 1:
        strength = 'Очень слабый пароль 😞'
    elif score <= 2:
        strength = 'Слабый пароль 😟'
    elif score <= 3:
        strength = 'Средний пароль 🤔'
    elif score <= 4:
        strength = 'Хороший пароль 😊'
    else:
        strength = 'Сильный пароль 🔥'

    return f"{strength} - {breach_feedback}"