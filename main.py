import bcrypt
import csv
import re
import requests

CSV_FILE = 'regno.csv'

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def is_valid_password(password):
    if (len(password) >= 8 and
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in "!@#$%^&*()-_+=" for c in password)):
        return True
    return False

def register_user():
    email = input("Enter your email: ")
    if not is_valid_email(email):
        print("Invalid email format.")
        return
    
    password = input("Enter your password: ")
    if not is_valid_password(password):
        print("Password must be at least 8 characters long, include uppercase, lowercase, numbers, and special characters.")
        return

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    security_question = input("Enter a security question for password recovery: ")
    security_answer = input("Enter the answer to your security question: ")

    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([email, hashed_password.decode('utf-8'), security_question, security_answer])
    
    print("User registered successfully!")

def login_user():
    email = input("Enter your email: ")
    password = input("Enter your password: ")

    with open(CSV_FILE, mode='r') as file:
        reader = csv.reader(file)
        for row in reader:
            stored_email, stored_password, _, _ = row
            if stored_email == email:
                if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
                    print("Login successful!")
                    return True
                else:
                    print("Invalid password.")
                    return False
    print("Email not found.")
    return False

def login_attempt():
    attempts = 5
    while attempts > 0:
        if login_user():
            return True
        attempts -= 1
        print(f"Login failed. You have {attempts} attempts left.")
    print("Too many failed login attempts. Try again later.")
    return False

def forgot_password():
    email = input("Enter your registered email: ")

    with open(CSV_FILE, mode='r') as file:
        reader = csv.reader(file)
        rows = list(reader)

    for i, row in enumerate(rows):
        stored_email, stored_password, security_question, security_answer = row
        if stored_email == email:
            print(f"Security Question: {security_question}")
            answer = input("Enter the answer: ")
            if answer == security_answer:
                new_password = input("Enter a new password: ")
                if not is_valid_password(new_password):
                    print("Password does not meet the required criteria.")
                    return
                hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                
                rows[i][1] = hashed_new_password.decode('utf-8')
                with open(CSV_FILE, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerows(rows)
                print("Password reset successfully!")
                return
            else:
                print("Incorrect answer to the security question.")
                return

    print("Email not found.")

def get_geolocation(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        if data['status'] == 'success':
            print(f"Country: {data.get('country')}")
            print(f"City: {data.get('city')}")
            print(f"Region: {data.get('regionName')}")
            print(f"Latitude: {data.get('lat')}")
            print(f"Longitude: {data.get('lon')}")
            print(f"Timezone: {data.get('timezone')}")
            print(f"ISP: {data.get('isp')}")
        else:
            print(f"Error: {data.get('message', 'Invalid IP address')}")
    else:
        print("Error: Unable to reach the API.")

def main():
    while True:
        print("\nWelcome to the IP Geolocation Console Application!")
        print("1. Register")
        print("2. Login")
        print("3. Forgot Password")
        print("4. Exit")
        
        option = input("Choose an option (1/2/3/4): ")

        if option == '1':
            register_user()
        elif option == '2':
            if login_attempt():
                ip_choice = input("Enter IP address to query (or press Enter to use your IP): ")
                ip_address = ip_choice if ip_choice else 'YOUR_IP'  
                get_geolocation(ip_address)
        elif option == '3':
            forgot_password()
        elif option == '4':
            print("Exiting the application. Goodbye!")
            break  
        else:
            print("Invalid option. Please choose a valid option (1/2/3/4).")

if __name__ == '__main__':
    main()

