# client.py
import socket, threading
from os import _exit
from time import sleep
from config import BUFFER_SIZE, HOST, PORT
from packet import system_request_packet, message_packet, parse_packet
from crypto import *
from logger import log


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.c_sock = None
        self.username = None
        self.public_key = None
        self.private_key = None
        self.public_keys_cache = {}
        self.pending_message = {}
        self.pending_verify = {}

    def start(self):
        while True:
            self.username = input("Enter your username: ").strip()
            if self.username != "":
                break
            else:
                log(level="error", message=f"Please enter valid username.")
                continue
        self.public_key, self.private_key = generate_key_pair()

        try:
            self.c_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.c_sock.connect((self.host, self.port))
            self.c_sock.send(
                system_request_packet(
                    from_user=self.username,
                    action="register",
                    payload={"username": self.username, "public_key": self.public_key},
                )
            )
            threading.Thread(target=self._recv_packet, daemon=True).start()
            self._handle_user_input()
        except ConnectionRefusedError:
            log(level="error", message="Count not connect to the server.")
        except KeyboardInterrupt:
            log(level="info", message="Exiting...")
        finally:
            self.c_sock.close()

    def _recv_packet(self):
        while True:
            try:
                raw_data = self.c_sock.recv(BUFFER_SIZE)
                if not raw_data:
                    log(level="info", message="Disconnected from the server.")
                    break

                data = parse_packet(data=raw_data)
                # print(data)
                data_type = data.get("type")
                if data_type == "system":
                    self._handle_system_packet_response(data=data)
                elif data_type == "message":
                    self._handle_message_packet_response(data=data)
            except (ConnectionResetError, ConnectionAbortedError):
                log(level="info", message="Connection to the server was lost.")
                break
            except Exception as e:
                log(level="error", message=f"An unexpected error occurred: {e}")
                break
        _exit(1)

    def _handle_message_packet_response(self, data: dict):
        from_user, enc_key, enc_message, signature = (
            data.get("from"),
            data.get("enc_key"),
            data.get("enc_message"),
            data.get("signature"),
        )

        try:
            dec_key = rsa_decrypt(cipher_text_b64=enc_key, private_pem=self.private_key)
            dec_message = aes_decrypt(cipher_text_b64=enc_message, key=dec_key)
            self._prepare_verify_message(
                from_user=from_user, signature=signature, dec_message=dec_message
            )
        except Exception as e:
            log(
                level="error",
                message=f"Failed to decrypt or verify the message signature: {e}",
            )

    def _handle_system_packet_response(self, data: dict):
        if data.get("status") == "error":
            log(level="error", message=f"{data.get('result')}")
            sleep(1)

            if "Username already taken" in data.get("result"):
                log(level="info", message="The client will now exit.")
                self.c_sock.close()
                _exit(1)

        elif data.get("status") == "ok":
            action = data.get("action")
            if action == "get_online_users":
                online_users = data.get("result")
                print("--- Online users ---")
                for user in online_users:
                    print(f" - {user}")
                print("--- ------------ ---")
            elif action == "get_public_key":
                target, public_key = (
                    data.get("result", {}).get("target"),
                    data.get("result", {}).get("public_key"),
                )
                self.public_keys_cache[target] = public_key
                # print(self.public_keys_cache)
                # print(self.pending_message)
                if target in self.pending_message:
                    message = self.pending_message.pop(target)
                    self._send_message(to_user=target, message=message)
                    log(level="info", message=f"Message sent to user '{target}'.")

                if target in self.pending_verify:
                    verify_message_target = self.pending_verify.pop(target)
                    signature = verify_message_target.get("signature")
                    dec_message = verify_message_target.get("dec_message")
                    # print(signature)
                    # print(message)
                    self._verify_message(
                        from_user=target, signature=signature, dec_message=dec_message
                    )
            elif action == "user_disconnected":
                target = data.get("result", {}).get("target")
                if target in self.public_keys_cache:
                    del self.public_keys_cache[target]

    def _handle_user_input(self):
        print("\nType 'help' for commands.")
        while True:
            sleep(0.1)
            user_input = input(f"{self.username} > ").strip()
            if user_input.lower() == "exit":
                break
            elif user_input.lower() == "online":
                self.c_sock.send(
                    system_request_packet(
                        from_user=self.username, action="get_online_users"
                    )
                )
            elif user_input.lower() == "help":
                print(
                    "Command:\n  help - Show help\n  online - List online users\n  @username <message> - Send a private message\n  exit - Close the client"
                )
            elif user_input.startswith("@"):
                try:
                    to_user, message = user_input[1:].split(" ", 1)
                    if not to_user or not message:
                        raise ValueError
                    self._prepare_send_message(to_user=to_user, message=message)

                except ValueError:
                    log(
                        level="error",
                        message="Invalid syntax. Use: @username <message>",
                    )
            else:
                if user_input:
                    log(
                        level="error",
                        message="Unknown command. Type 'help' for instructions.",
                    )

    def _prepare_verify_message(self, from_user: str, signature: str, dec_message: str):
        if from_user in self.public_keys_cache:
            self._verify_message(
                from_user=from_user, signature=signature, dec_message=dec_message
            )
        else:
            # print("Not sender public key")
            self.pending_verify[from_user] = {
                "signature": signature,
                "dec_message": dec_message,
            }
            log(
                level="info",
                message=f"Waiting for '{from_user}' public key to verify the message...",
            )
            self.c_sock.send(
                system_request_packet(
                    from_user=self.username,
                    action="get_public_key",
                    payload={
                        "target": from_user,
                    },
                )
            )

    def _verify_message(self, from_user: str, signature: str, dec_message: str):
        sender_public_key = self.public_keys_cache.get(from_user)
        verify_message = verify_signature(
            public_pem=sender_public_key, signature_b64=signature, message=dec_message
        )
        if verify_message == True:
            print(f"[{from_user}] -> you: {dec_message}")
        else:
            log(
                level="error",
                message=f"Signature verification failed for the message from '{from_user}'.",
            )

    def _prepare_send_message(self, to_user: str, message: str):
        if to_user == self.username:
            log(level="error", message=f"You cannot send a message to yourself.")
            return

        if to_user in self.public_keys_cache:
            self._send_message(to_user=to_user, message=message)
        else:
            log(
                level="info",
                message=f"Public key for '{to_user}' not found. Requesting it from the server...",
            )
            sleep(1)
            self.pending_message[to_user] = message
            self.c_sock.send(
                system_request_packet(
                    from_user=self.username,
                    action="get_public_key",
                    payload={
                        "target": to_user,
                    },
                )
            )
        # print(self.public_keys_cache)
        # print(self.pending_message)

    def _send_message(self, to_user: str, message: str):
        try:
            recipient_public_key = self.public_keys_cache[to_user]
            # key = b"01234567890123456789012345678901"
            key = get_random_bytes(32)
            enc_key = rsa_encrypt(plain_text=key, public_pem=recipient_public_key)
            enc_message = aes_encrypt(plain_text=message, key=key)
            signature = create_signature(private_pem=self.private_key, message=message)
            self.c_sock.send(
                message_packet(
                    from_user=self.username,
                    to_user=to_user,
                    enc_key=enc_key,
                    enc_message=enc_message,
                    signature=signature,
                )
            )
        except Exception as e:
            log(level="error", message=f"Failed to send the message: {e}")


if __name__ == "__main__":
    client = Client(HOST, PORT)
    client.start()
