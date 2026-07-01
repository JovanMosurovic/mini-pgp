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
        self.sign = sign,
        self.encrypt = encrypt,
        self.compress = compress,
        self.radix64 = radix64,

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


