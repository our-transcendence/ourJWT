import jwt
import os


class Decoder:
    pub_key = os.getenv("PUB_KEY")

    class RefusedToken(Exception):
        pass

    class ExpiredToken(Exception):
        pass

    @staticmethod
    def decode(to_decode):
        try:
            token = jwt.decode(jwt=to_decode,
                               key=Decoder.pub_key,
                               algorithms=["RS256"],
                               issuer="OUR_Transcendance")
        except (jwt.DecodeError,
                jwt.InvalidIssuerError,
                jwt.InvalidSignatureError):
            raise Decoder.RefusedToken()
        except jwt.ExpiredSignatureError:
            raise Decoder.ExpiredToken()
        return token
