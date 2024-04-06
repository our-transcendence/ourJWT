import jwt
import os

import OUR_exception


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
            raise OUR_exception.NoKey()

