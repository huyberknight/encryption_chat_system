# server.py
import socket, threading, json
from config import BUFFER_SIZE, HOST, PORT
from packet import parse_packet, system_response_packet, create_packet
from logger import log
from crypto import (
    generate_key_pair,
    create_signature,
    rsa_decrypt,
    aes_encrypt,
    aes_decrypt,
)


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

            ca_public, ca_private = generate_key_pair()
            s_public_key, self.s_private_key = generate_key_pair()
            self.certification = {
                "server_name": "RealServer",
                "public_key": s_public_key,
            }

            self.signature_certification = create_signature(
                private_pem=ca_private, message=json.dumps(self.certification)
            )

            with open("ca_public.pem", "w") as f:
                f.write(ca_public)

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
        """
        Receive packets from the client.
        """
        username = None
        try:
            while True:
                raw_data = c_sock.recv(BUFFER_SIZE)
                if not raw_data:
                    for other_user in self.clients:
                        if other_user != self.clients:
                            other_user_session_key = self.clients.get(other_user, {}).get(
                                "session_key"
                            )
                            other_user_sock: socket.socket = self.clients.get(
                                other_user, {}
                            ).get("socket")
                            enc_result = aes_encrypt(
                                plain_text=json.dumps(
                                    {"status": "ok", "target": username}
                                ),
                                key=other_user_session_key,
                            )
                            other_user_sock.send(
                                system_response_packet(
                                    to_user=other_user,
                                    action="user_disconnected",
                                    result=enc_result,
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
        """
        The server processes message packets sent from the client.
        """
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
            error_message = f"User '{to_user}' was not found or is offline."
            enc_result = aes_encrypt(
                plain_text=json.dumps(
                    {
                        "status": "error",
                        "message": f"Cannot deliver your message. {error_message}",
                    }
                ),
                key=self.c_session_key,
            )
            c_sock.send(
                system_response_packet(
                    to_user=from_user,
                    action="",
                    result=enc_result,
                )
            )
            log(level="info", message=f"Error sent to '{from_user}': {error_message}")

    def _handle_system_request(self, c_sock: socket.socket, data: dict):
        """
        The server handles system type packets sent from the client.
        """
        action = data.get("action")
        from_user = data.get("from")
        if action == "handshake":
            c_sock.send(
                system_response_packet(
                    to_user=from_user,
                    action=action,
                    result={
                        "message": "hello_client",
                        "status": "ok",
                        "certification": self.certification,
                        "signature": self.signature_certification,
                    },
                )
            )
        elif action == "register":
            enc_session_key = data.get("payload", {}).get("session_key")
            enc_public_key = data.get("payload", {}).get("public_key")
            username = data.get("payload", {}).get("username")
            session_key = rsa_decrypt(
                cipher_text_b64=enc_session_key, private_pem=self.s_private_key
            )
            c_public_key = aes_decrypt(cipher_text_b64=enc_public_key, key=session_key)
            with self.lock:
                if username in self.clients:
                    error_message = f"This username is already taken. Please choose a different one."
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user,
                            action=action,
                            result=aes_encrypt(
                                plain_text=json.dumps(
                                    {
                                        "status": "error",
                                        "message": error_message,
                                    }
                                ),
                                key=session_key,
                            ),
                        )
                    )
                    c_sock.close()
                else:
                    self.clients[from_user] = {
                        "session_key": session_key,
                        "socket": c_sock,
                        "public_key": c_public_key,
                    }
                    log(
                        level="info",
                        message=f"User '{from_user}' has registered and is now connected.",
                    )
        else:
            self.c_session_key = self.clients.get(from_user, {}).get("session_key")
            enc_payload = data.get("payload")
            payload = (
                json.loads(
                    aes_decrypt(cipher_text_b64=enc_payload, key=self.c_session_key)
                )
                if enc_payload != None
                else None
            )
            if action == "get_online_users":
                with self.lock:
                    online_users = list(self.clients.keys())

                if online_users:
                    enc_result = aes_encrypt(
                        plain_text=json.dumps({"status": "ok", "users": online_users}),
                        key=self.c_session_key,
                    )
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user, action=action, result=enc_result
                        )
                    )
                else:
                    enc_result = aes_encrypt(
                        plain_text=json.dumps(
                            {
                                "status": "error",
                                "message": "Unable to retrieve the list of online users.",
                            }
                        ),
                        key=self.c_session_key,
                    )
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user, action=action, result=enc_result
                        )
                    )
                log(
                    level="info",
                    message=f"User '{from_user}' requested the list of online users.",
                )
            elif action == "get_public_key":
                # print(payload)
                target = payload.get("target")
                with self.lock:
                    target_public_key = self.clients.get(target, {}).get("public_key")

                log(
                    level="info",
                    message=f"User '{from_user}' requested the public key of '{target}'.",
                )

                if target_public_key:
                    enc_result = aes_encrypt(
                        plain_text=json.dumps(
                            {
                                "status": "ok",
                                "target": target,
                                "public_key": target_public_key,
                            }
                        ),
                        key=self.c_session_key,
                    )
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user,
                            action="get_public_key",
                            result=enc_result,
                        )
                    )
                    log(
                        level="info",
                        message=f"Sent public key of '{target}' to '{from_user}'.",
                    )
                else:
                    error_message = f"The user may be offline or does not exist."
                    enc_result = aes_encrypt(
                        plain_text=json.dumps(
                            {
                                "status": "error",
                                "message": f"Unable to retrieve the public key of '{target}'. {error_message}",
                            }
                        ),
                        key=self.c_session_key,
                    )
                    c_sock.send(
                        system_response_packet(
                            to_user=from_user,
                            action="get_public_key",
                            result=enc_result,
                        )
                    )
                    log(
                        level="info",
                        message=f"Failed to send public key of '{target}' to '{from_user}': {error_message}.",
                    )

    def _remove_client(self, username: str):
        """
        Remove client from list.
        """
        with self.lock:
            if username in self.clients:
                del self.clients[username]
        log(level="info", message=f"User '{username}' has disconnected.")


if __name__ == "__main__":
    server = Server(HOST, PORT)
    server.start()
