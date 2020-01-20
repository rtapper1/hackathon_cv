import time
import hmac
import hashlib
import base64
import sys
#import urllib.parse
if sys.version_info.major == 2:
    import urllib
else:
    import urllib.parse
#from requests.utils import requote_uri

def get_auth_token(sb_name, eh_name, sas_name, sas_value):
    """
    Returns an authorization token dictionary
    for making calls to Event Hubs REST API.
    """
    if sys.version_info.major == 2:
        uri = urllib.pathname2url("https://{}.servicebus.windows.net/{}" \
                                      .format(sb_name, eh_name))
    else:
        uri = urllib.parse.quote_plus("https://{}.servicebus.windows.net/{}" \
                                  .format(sb_name, eh_name))
    sas = sas_value.encode('utf-8')
    expiry = str(int(time.time() + 10000))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    if sys.version_info.major == 2:
        signature = urllib.pathname2url(base64.b64encode(signed_hmac_sha256.digest()))
    else:
        signature = urllib.parse.quote(base64.b64encode(signed_hmac_sha256.digest()))
    return  {"sb_name": sb_name,
             "eh_name": eh_name,
             "token":'SharedAccessSignature sr={}&sig={}&se={}&skn={}' \
                     .format(uri, signature, expiry, sas_name)
            }

'''
def get_auth_token_orig(sb_name, eh_name, sas_name, sas_value):
    """
    Returns an authorization token dictionary
    for making calls to Event Hubs REST API.
    """
    uri = urllib.parse.quote_plus("https://{}.servicebus.windows.net/{}" \
                                  .format(sb_name, eh_name))
    sas = sas_value.encode('utf-8')
    expiry = str(int(time.time() + 10000))
    string_to_sign = (uri + '\n' + expiry).encode('utf-8')
    signed_hmac_sha256 = hmac.HMAC(sas, string_to_sign, hashlib.sha256)
    signature = urllib.parse.quote(base64.b64encode(signed_hmac_sha256.digest()))
    return  {"sb_name": sb_name,
             "eh_name": eh_name,
             "token":'SharedAccessSignature sr={}&sig={}&se={}&skn={}' \
                     .format(uri, signature, expiry, sas_name)
            }
'''
#print(get_auth_token('pechackatoncv', 'peoplecounter', 'testPeopleCounter', 'pzacp1orn4fchWGrA0V8F+ip8aNOdGPOCHtu3zDyctA='))
