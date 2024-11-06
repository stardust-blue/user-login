import socket


class AuthClient:
    def __init__(self, host="127.0.0.1", port=6969):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        print(f"Connected to the server at {host}:{port}")

    def login(self):
        print("Logging in...")
        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return

        password = input("Password: ").strip()
        if not password:
            print("Password cannot be empty.")
            return

        self.client_socket.sendall(username.encode())
        self.client_socket.sendall(password.encode())

        response = self.client_socket.recv(1024).decode()
        if response == "LOGIN_SUCCESS":
            print("You are now logged in.")
        elif response == "LOGIN_FAILED":
            print("User does not exist or password is incorrect.")

    def register(self):
        print("Registering a new account...")
        username = input("Username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return

        self.client_socket.sendall(username.encode())
        response = self.client_socket.recv(1024).decode()

        if response == "USR_EXISTS":
            print("Username already exists. Please choose a different one.")
            return

        if response == "USR_AVAILABLE":
            password = input("Password: ").strip()
            if not password:
                print("Password cannot be empty.")
                return

            self.client_socket.sendall(password.encode())

            response = self.client_socket.recv(1024).decode()

            if response == "REGISTRATION_SUCCESS":
                print("Registration successful! You can now log in.")
            else:
                print("Registration failed. Please try again.")

    def start(self):
        while True:
            mode = input("Would you like to login or register? (l/r): ").lower().strip()

            if mode not in ["l", "r"]:
                print("Invalid choice. Please enter 'l' for login or 'r' for register.")
                continue

            self.client_socket.sendall(mode.encode())

            if mode == "l":
                self.login()
            elif mode == "r":
                self.register()

            retry = input("Do you want to try again? (y/n): ").lower().strip()
            if retry != "y":
                print("Exiting...")
                break

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.client_socket.close()
        print("Connection closed.")


def main():
    try:
        with AuthClient() as client:
            client.start()
    except Exception as e:
        print(f"Error occurred: {e}")


if __name__ == "__main__":
    main()
