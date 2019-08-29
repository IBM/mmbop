"""
Uses Falcon to implement simple API wrapper for mmbop
"""
import configparser
import hashlib
import falcon
import mmbop

class AuthToken(object):
    """
    Implements simple authentication token
    """

    # Contains the string (hexdigest) of the SHA224 hashing of the token
    AUTH_TOKEN = None
    # Location where hashed token string can be found
    TOKEN_FILE = './mmbop_api.ini'
    # Key in the token file, the value of which is the hashed token string
    TOKEN_FIELD = 'token'

    def __init__(self):
        if not self.__class__.AUTH_TOKEN:
            self._get_token()
        if not self.__class__.AUTH_TOKEN:
            raise falcon.HTTPError(falcon.HTTP_500, 'Auth Error', 'Unable to find auth token')

    def _get_token(self):
        """
        Attempt to read token file and fill AUTH_TOKEN
        """
        config = configparser.ConfigParser()
        try:
            config.read(self.__class__.TOKEN_FILE)
            default_config = config['DEFAULT']
            self.__class__.AUTH_TOKEN = default_config.get(self.__class__.TOKEN_FIELD, None)
        except (IOError, configparser.Error):
            pass

    def process_request(self, req, _):
        """
        Falcon required method for handling request and (in this case)
        ensuring the provided token is correct
        """
        token = req.get_header('Authorization')
        if not token:
            desc = ('Provide an authentication token in header request')
            raise falcon.HTTPUnauthorized('Auth token required', desc)
        if not self._token_is_valid(token):
            desc = ('Invalid authentication token')
            raise falcon.HTTPUnauthorized('Invalid auth token', desc)

    def _token_is_valid(self, token):
        return bool(self._hash(token) == self.__class__.AUTH_TOKEN)

    @staticmethod
    def _hash(token):
        """
        Perform SHA224 hash on given token and return string (hexdigest)
        """
        return hashlib.sha224(str.encode(token)).hexdigest()

class Base(object):
    """
    Base API class to initialize rndc
    """

    def __init__(self, rndc_instance):
        self.rndc = rndc_instance


class Status(Base):
    """
    Handle status requests
    """

    def on_get(self, _, resp):
        """
        Return result of 'rndc status' on GET request
        """
        resp.body = (self.rndc.status())

class ZoneInfo(Base):
    """
    Handle status request for specific domain
    """

    def on_get(self, _, resp, domain):
        """
        Return result of 'rndc zoneinfo <zone>' on GET request
        """
        resp.body = (self.rndc.zonestatus(domain))

class ZoneList(Base):
    """
    Handle list of active zones
    """

    def on_get(self, _, resp):
        """
        Return result of 'rndc dumpdb' with zone checking
        """
        resp.body = (self.rndc.list_zones())

class Modify(Base):
    """
    Handle add/delete requests
    """

    def on_post(self, req, resp):
        """
        Adding a zone via POST request
        """
        zone_name = req.media.get('domain')
        if not zone_name:
            resp.status = falcon.HTTP_400
            resp.body = ('Missing domain parameter')
        else:
            (success, message) = self.rndc.add(zone_name)
            if success:
                resp.status = falcon.HTTP_201
                resp.location = self.rndc.zonestatus(zone_name)
                resp.body = (message)
            else:
                resp.status = falcon.HTTP_400
                resp.body = (message)

    def on_delete(self, req, resp):
        """
        Removing a zone via DELETE request
        """
        zone_name = req.media.get('domain')
        if not zone_name:
            resp.statuss = falcon.HTTP_400
            resp.body = ('Missing domain parameter')
        else:
            (success, message) = self.rndc.delete(zone_name)
            if success:
                resp.body = (message)
            else:
                resp.status = falcon.HTTP_400
                resp.body = (message)


CONF_FILE = './mmbop.ini'

MY_CONF = mmbop.read_config(CONF_FILE)
MY_RNDC = mmbop.RNDC.create(**MY_CONF)
APP = falcon.API(middleware=[AuthToken()])
STATUS = Status(MY_RNDC)
ZONEINFO = ZoneInfo(MY_RNDC)
MODIFY = Modify(MY_RNDC)
ZONELIST = ZoneList(MY_RNDC)
APP.add_route('/status', STATUS)
APP.add_route('/modify', MODIFY)
APP.add_route('/zonelist', ZONELIST)
APP.add_route('/zoneinfo/{domain}', ZONEINFO)
