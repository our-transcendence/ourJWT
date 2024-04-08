import jwt
import os

import OUR_exception

good_iss = "OUR_Transcendence"


class Decoder:
    pub_key = os.getenv("PUB_KEY")


    @staticmethod
    def decode(to_decode):
        if Decoder.pub_key == None:
            raise OUR_exception.NoKey()
        try:
            token = jwt.decode(jwt=to_decode,
                               key=Decoder.pub_key,
                               algorithms=["RS256"],
                               issuer="OUR_Transcendance")
        except (jwt.DecodeError,
                jwt.InvalidIssuerError,
                jwt.InvalidSignatureError):
            raise OUR_exception.RefusedToken()
        except jwt.ExpiredSignatureError:
            raise OUR_exception.ExpiredToken()
        return token


class Encoder:
    private_key = os.getenv("PRIV_KEY")

    @staticmethod
    def encode(to_encode):
        if Encoder.private_key == None:
    def encode(to_encode, type):
        if type != "refresh" and type != "auth":
            raise OUR_exception.BadSubject()
        if Encoder.private_key is None:
            raise OUR_exception.NoKey()
        if not isinstance(to_encode, dict):
            raise TypeError("Payload not a dict")
        to_encode["iss"] = good_iss
        to_encode["sub"] = type
        encoded = jwt.encode(payload=to_encode,
                             key=Encoder.private_key,
                             algorithm="RS256")
        return encoded
