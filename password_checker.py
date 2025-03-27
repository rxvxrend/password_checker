from validators import analyze_password

def test_runner():
    passwords = [
        '12345678', 'password123', 'qwerty9876', 'Aaaa1111',
        'Admin2024', 'helloworld1', 'Hello2024', 'Securepass1',
        'Pass_word2023', 'G!tH#b_4ev3r', 'Q@zX!sC2025',
        'Dood12iq!!', 'R@nd0m_P@ss123'
    ]
    for password in passwords:
        analysis = analyze_password(password)
        print(f'{password} - {analysis}')

def main():
    user_password = input('Введите пароль: ').strip()
    analysis = analyze_password(user_password)
    print(f'{user_password} - {analysis}')

if __name__ == "__main__":
    test_runner()
    main()