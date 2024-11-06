import sqlite3
import socket
import threading
import bcrypt


class AuthServer:
    def __init__(self, database="users.db", host="127.0.0.1", port=6969):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        print(f"Server started. Listening on {host}:{port}")

        self.conn = sqlite3.connect(database, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(255) PRIMARY KEY,
                password_hash VARCHAR(255) NOT NULL
            );
        """)
        print(f"Connected to database: {database}")

        self.lock = threading.Lock()

    def start(self):
        while True:
            try:
                client_socket, client_address = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                ).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def handle_client(self, client_socket, client_address):
        print(f"Client connected: {client_address}")
        try:
            while True:
                mode = client_socket.recv(1024).decode().lower()
                if mode not in ["l", "r"]:
                    client_socket.sendall(
                        "Invalid input. Please enter 'l' for login or 'r' for register.".encode()
                    )
                    continue

                if mode == "l":
                    self.login(client_socket)
                else:
                    self.register(client_socket)

        except ConnectionResetError:
            print(f"Client disconnected: {client_address}.")
        except Exception as e:
            print(f"Error while handling client {client_address}: {e}")
        finally:
            client_socket.close()

    def login(self, client_socket):
        username = client_socket.recv(1024).decode().strip()
        password = client_socket.recv(1024).decode().strip()

        with self.lock:
            self.cursor.execute(
                "SELECT password_hash FROM users WHERE username = ?;",
                (username,),
            )
            result = self.cursor.fetchone()

        if result is not None and bcrypt.checkpw(password.encode(), result[0].encode()):
            client_socket.sendall("LOGIN_SUCCESS".encode())
            print(f"User {username} successfully logged in.")
        else:
            client_socket.sendall("LOGIN_FAILED".encode())

    def register(self, client_socket):
        username = client_socket.recv(1024).decode().strip()

        with self.lock:
            self.cursor.execute("SELECT * FROM users WHERE username = ?;", (username,))
            if self.cursor.fetchone():
                client_socket.sendall("USR_EXISTS".encode())
                return

            client_socket.sendall("USR_AVAILABLE".encode())

        password_hash = bcrypt.hashpw(
            client_socket.recv(1024).decode().strip().encode(), bcrypt.gensalt()
        ).decode()

        with self.lock:
            self.cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?);",
                (username, password_hash),
            )
            self.conn.commit()

        client_socket.sendall("REGISTRATION_SUCCESS".encode())
        print(f"{username} successfully registered.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()
        self.conn.close()
        print("Shutting down...")


def main():
    try:
        with AuthServer() as server:
            server.start()
    except Exception as e:
        print(f"Error occurred: {e}")


if __name__ == "__main__":
    main()
