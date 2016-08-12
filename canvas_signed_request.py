import base64
import hashlib
import hmac


class SignedRequest:

    # Construct a SignedRequest based on the stringified version of it.
    def __init__(self, consumer_secret, signed_request):
        self.consumer_secret = consumer_secret
        self.signed_request = signed_request

    # Validates the signed request by verifying the key, then returns
    # the json string.
    def verifyAndDecode(self):

        # Validate secret and signed request string.
        assert self.consumer_secret != None, 'No consumer secret found in environment [CANVAS_CONSUMER_SECRET].'
        assert self.signed_request != None, 'Signed request parameter required.'

        # 1) Split the signed request into signature and payload.
        request_array = self.signed_request.split('.')

        assert len(request_array) == 2, 'Incorrectly formatted signed request.'

        signature = request_array[0]
        payload = request_array[1]

        # 2) Verify the contents of the payload by first validating the authenticity
        #    of the signature.
        decoded_signature = base64.b64decode(signature)

        this_hmac = hmac.new(self.consumer_secret.encode('utf-8'),
                             payload.encode('utf-8'),
                             hashlib.sha256)

        assert decoded_signature == this_hmac.digest(), 'Signed request has been tampered with.'

        # 3) Decode the base64 encoded payload of the canvas request.
        json_string = base64.b64decode(payload)

        return json_string
