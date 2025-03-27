import hashlib
import requests

def hash_password(password):
    return hashlib.sha1(password.encode()).hexdigest().upper()

def get_pwned_data(prefix):
    url = f'https://api.pwnedpasswords.com/range/{prefix}'
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return dict(line.split(":") for line in response.text.splitlines())
        return None
    except requests.RequestException:
        return None

def check_password_online(password):
    hashed_password = hash_password(password)
    prefix, suffix = hashed_password[:5], hashed_password[5:]

    hashes = get_pwned_data(prefix)
    if hashes is None:
        return 0, "Ошибка при запросе к API утечек."

    count = int(hashes.get(suffix, '0'))
    if count > 100_000:
        return -10, "❌ Этот пароль слишком распространён! Выберите другой."
    elif count > 500:
        return -2, f"Пароль найден в утечках {count} раз."
    elif count > 0:
        return -1, f"Пароль найден в утечках {count} раз."
    return 0, "Пароль не найден в утечках."