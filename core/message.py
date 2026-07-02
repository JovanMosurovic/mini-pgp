import base64
import json
import zlib
from core.crypto import *
from core.keyrings import *
from core.keyrings import _now, _key_id_hex, _lock_private_key, _unlock_private_key

def _b64e(data_bytes):
    return base64.b64encode(data_bytes).decode()


def _b64d(data_text):
    return base64.b64decode(data_text.encode())


def _json_bytes(obj):
    return json.dumps(obj, sort_keys=True).encode()


def _json_obj(data_bytes):
    return json.loads(data_bytes.decode())

class PgpMessage:
    def __init__(
            self,

            # services
            sign = False,
            encrypt = False,
            compress = False,
            radix64 = False,

            # message
            data = "",
            filename = "",
            timestamp = "",

            # signature
            signature = None,
            signature_timestamp = None,
            sender_public_key_id = None,
            leading_two_octets = None,

            # session key
            session_key = None,
            recipient_public_key_id = None,
            algorithm = None
    ):
        # services
        self.sign = sign
        self.encrypt = encrypt
        self.compress = compress
        self.radix64 = radix64

        # message
        self.data = data
        self.filename = filename
        self.timestamp = timestamp

        # signature
        self.signature = signature
        self.signature_timestamp = signature_timestamp
        self.sender_public_key_id = sender_public_key_id
        self.leading_two_octets = leading_two_octets

        # session key
        self.session_key = session_key
        self.recipient_public_key_id = recipient_public_key_id
        self.algorithm = algorithm

    @classmethod
    def create(cls, filename, data_bytes):
        return cls(
            filename=filename,
            timestamp=_now(),
            data=_b64e(data_bytes)
        )

    def get_data_bytes(self):
        return _b64d(self.data)

    def _inner_packet(self):
        return {
            "filename": self.filename,
            "timestamp": self.timestamp,
            "data": self.data,
            "signature": self.signature,
            "signature_timestamp": self.signature_timestamp,
            "sender_public_key_id": self.sender_public_key_id,
            "leading_two_octets": self.leading_two_octets,
        }

    def _outer_packet(self):
        return {
            "sign": self.sign,
            "encrypt": self.encrypt,
            "compress": self.compress,
            "radix64": self.radix64,
            "data": self.data,
            "session_key": self.session_key,
            "recipient_public_key_id": self.recipient_public_key_id,
            "algorithm": self.algorithm,
        }

    def send(
        self,
        path,
        private_ring = None,
        sender_public_key_id = None,
        sender_password=None,
        public_ring=None,
        recipient_public_key_id=None,
        algorithm="AES128",
        sign=False,
        encrypt=False,
        compress=False,
        radix64=False
    ):
        self.sign = bool(sign)
        self.encrypt = bool(encrypt)
        self.compress = bool(compress)
        self.radix64 = bool(radix64)

        message_bytes = self.get_data_bytes()

        if self.sign:
            private_key = private_ring.get_private_key(sender_public_key_id, sender_password)
            message_hash = sha1(message_bytes)

            self.signature = _b64e(rsa_sign(private_key, message_bytes))
            self.signature_timestamp = _now()
            self.sender_public_key_id = sender_public_key_id
            self.leading_two_octets = message_hash[:2].hex().upper()

        body = _json_bytes(self._inner_packet())

        if self.compress:
            body = zlib.compress(body)

        if self.encrypt:
            public_key = public_ring.get_public_key(recipient_public_key_id)
            session_key = new_session_key(algorithm)

            encrypted_body = symmetrical_encrypt(algorithm, session_key, body)
            encrypted_session_key = rsa_encrypt(public_key, session_key)

            self.data = _b64e(encrypted_body)
            self.session_key = _b64e(encrypted_session_key)
            self.recipient_public_key_id = recipient_public_key_id
            self.algorithm = algorithm
        else:
            self.data = _b64e(body)
            self.session_key = None
            self.recipient_public_key_id = None
            self.algorithm = None

        output = _json_bytes(self._outer_packet())

        if self.radix64:
            output = base64.b64encode(output)

        with open(path, "wb") as f:
            f.write(output)






