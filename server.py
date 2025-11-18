# server.py
import socket, threading, json
from config import BUFFER_SIZE, HOST, PORT
from packet import parse_packet, system_response_packet, create_packet
from logger import log


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.s_sock = None
        self.clients = {}
        self.lock = threading.Lock()

    def start(self):
        try:
            self.s_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s_sock.bind((self.host, self.port))
            self.s_sock.listen()
            log(level="info", message=f"Server is starting...")
            log(level="info", message=f"Server listening on {self.host}:{self.port}")
            while True:
                c_sock, c_addr = self.s_sock.accept()
                log(
                    level="info",
                    message=f"New client connected from {c_addr[0]}:{c_addr[1]}",
                )
                threading.Thread(
                    target=self._handle_client, args=(c_sock, c_addr), daemon=True
                ).start()
        except OSError as e:
            log(level="error", message=f"{e}")
        except KeyboardInterrupt:
            log(level="info", message=f"Server shutting down...")
        finally:
            self.s_sock.close()

    def _handle_client(self, c_sock: socket.socket, c_addr):
        username = None
        try:
            while True:
                raw_data = c_sock.recv(BUFFER_SIZE)
                if not raw_data:
                    for other_user in self.clients:
                        if other_user != self.clients:
                            other_user_sock: socket.socket = self.clients.get(
                                other_user, {}
                            ).get("socket")
                            other_user_sock.send(
                                system_response_packet(
                                    to_user=other_user,
                                    action="user_disconnected",
                                    status="ok",
                                    result={"target": username},
                                )
                            )
                    if username and username in self.clients:
                        self._remove_client(username)
                    break

                try:
                    data = parse_packet(raw_data)
                    # print(data)
                    if data.get("action") == "register" and "from" in data:
                        username = data.get("from")

                    data_type = data.get("type")
                    if data_type == "system":
                        self._handle_system_request(c_sock, data)
                    elif data_type == "message":
                        self._handle_message_request(c_sock, data)
                except json.JSONDecodeError as e:
                    log(
                        level="info",
                        message=f"Received invalid data from {username}: {e}",
                    )
                    continue

        except (ConnectionResetError, ConnectionAbortedError, OSError):
            log(level="info", message=f"Connection lost with {c_addr[0]}:{c_addr[1]}")
        finally:
            c_sock.close()

    def _handle_message_request(self, c_sock: socket.socket, data: dict):
        from_user, to_user, enc_message = (
            data.get("from"),
            data.get("to"),
            data.get("enc_message"),
        )
        with self.lock:
            recipient_sock: socket.socket = self.clients.get(to_user, {}).get("socket")

        if recipient_sock:
            recipient_sock.send(create_packet(data))
            log(
                level="info",
                message=f"Message relayed from '{from_user}' to '{to_user}': {enc_message}",
            )
        else:
            error_msg = f"User '{to_user}' was not found or is offline."
            c_sock.send(
                system_response_packet(
                    to_user=from_user,
                    action="",
                    status="error",
                    result=f"Cannot deliver your message. {error_msg}",
                )
            )
            log(level="info", message=f"Error sent to '{from_user}': {error_msg}")

    def _handle_system_request(self, c_sock: socket.socket, data: dict):
        action = data.get("action")
        from_user = data.get("from")
        if action == "register":
            username = data.get("payload", {}).get("username")
            public_key = data.get("payload", {}).get("public_key")

            with self.lock:
                if username in self.clients:
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user,
                            action=action,
                            status="error",
                            result=f"This username is already taken. Please choose a different one.",
                        )
                    )
                    c_sock.close()
                else:
                    self.clients[username] = {
                        "socket": c_sock,
                        "public_key": public_key,
                    }
                    log(
                        level="info",
                        message=f"User '{from_user}' has registered and is now connected.",
                    )
            # print(self.clients)
            # print(self.public_keys)
        elif action == "get_online_users":
            with self.lock:
                online_users = list(self.clients.keys())

            if online_users:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action=action,
                        status="ok",
                        result=online_users,
                    )
                )
            else:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action=action,
                        status="error",
                        result=f"Unable to retrieve the list of online users.",
                    )
                )
            log(
                level="info",
                message=f"User '{from_user}' requested the list of online users.",
            )
        elif action == "get_public_key":
            target = data.get("payload", {}).get("target")
            with self.lock:
                target_public_key = self.clients.get(target, {}).get("public_key")

            log(
                level="info",
                message=f"User '{from_user}' requested the public key of '{target}'.",
            )
            if target_public_key:
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action="get_public_key",
                        status="ok",
                        result={"target": target, "public_key": target_public_key},
                    )
                )
                log(
                    level="info",
                    message=f"Sent public key of '{target}' to '{from_user}'.",
                )
            else:
                error_msg = f"The user may be offline or does not exist."
                c_sock.send(
                    system_response_packet(
                        to_user=from_user,
                        action="get_public_key",
                        status="error",
                        result=f"Unable to retrieve the public key of '{target}'. {error_msg}",
                    )
                )
                log(
                    level="info",
                    message=f"Failed to send public key of '{target}' to '{from_user}': {error_msg}.",
                )

    def _remove_client(self, username: str):
        with self.lock:
            if username in self.clients:
                del self.clients[username]
        log(level="info", message=f"User '{username}' has disconnected.")


if __name__ == "__main__":
    server = Server(HOST, PORT)
    server.start()
