import jwt
from django.http import HttpRequest, response

import OUR_exception, OUR_class

def auth_required(function):
    def wrapper(request: HttpRequest, *args, **kwargs):
        auth = request.COOKIES.get("auth_token", None)
        if auth is None:
            return response.HttpResponse(status=412, reason="No auth token detected")
        try:
            auth_decoded = OUR_class.Decoder.decode(auth)
        except OUR_exception.NoKey:
            print("NO PUBLIC KEY BIG ERROR") #TODO check with beroux to standardize thoose type of error
        except (OUR_exception.BadSubject, OUR_exception.RefusedToken):
            return response.HttpResponse(status=412, reason="Bad auth token")
        except OUR_exception.ExpiredToken:
            return response.HttpResponse(status=412, reason="Expired auth token") #TODO: generate new auth token directly from here
            auth_decoded = decoder.decode(auth_token)
        return function(request)

    return wrapper
