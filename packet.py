# packet.py
import json


def create_packet(data: dict) -> bytes:
    return json.dumps(data).encode()


def parse_packet(data: bytes) -> dict:
    return json.loads(data.decode())


def system_request_packet(from_user: str, action: str, payload=None):
    return create_packet(
        {
            "type": "system",
            "action": action,
            "from": from_user,
            "to": "server",
            "payload": payload,
        }
    )


def system_response_packet(to_user: str, action, result=None):
    return create_packet(
        {
            "type": "system",
            "action": action,
            "from": "server",
            "to": to_user,
            "result": result,
        }
    )


def message_packet(
    from_user: str, to_user: str, enc_key: str, enc_message: str, signature: str
):
    return create_packet(
        {
            "type": "message",
            "from": from_user,
            "to": to_user,
            "enc_key": enc_key,
            "enc_message": enc_message,
            "signature": signature,
        }
    )
