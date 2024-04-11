import jwt

import OUR_exception

good_iss = "OUR_Transcendence"


class Decoder:
    pub_key: str

    def __init__(self, pub_key):
        self.pub_key = pub_key
        if self.pub_key is None:
            raise OUR_exception.NoKey



    def decode(self, to_decode):
        """
        decode the given JWT into a dict.

        Args:
            to_decode (str): The JWT to be decoded.

        Raises:
            OUR_exception.BadSubject: If the type is not "refresh" or "auth".
            OUR_exception.RefusedToken: If the token is invalid
            OUR_exception.ExpiredToken: if the token is expired

        Returns:
            dict: The decoded JWT.
        """
        try:
            token = jwt.decode(jwt=to_decode,
                               key=self.pub_key,
                               algorithms=["RS256"],
                               issuer=good_iss)
        except (jwt.DecodeError,
                jwt.InvalidIssuerError,
                jwt.InvalidSignatureError):
            raise OUR_exception.RefusedToken()
        except jwt.ExpiredSignatureError:
            raise OUR_exception.ExpiredToken()
        if token["sub"] != "auth" and token["sub"] != "refresh":
            raise OUR_exception.BadSubject
        return token




class Encoder:
    private_key: str

    def __init__(self, priv_key):
        self.private_key = priv_key
        if self.private_key is None:
            raise OUR_exception.NoKey

    def encode(self, to_encode, type):
        """
        Encodes the given payload into a JWT (JSON Web Token).

        Args:
            to_encode (dict): The payload to be encoded into the JWT.
            type (str): The type of the token, must be either "refresh" or "auth".

        Raises:
            OUR_exception.BadSubject: If the type is not "refresh" or "auth".
            TypeError: If the payload is not a dictionary.

        Returns:
            str: The encoded JWT.
        """
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
