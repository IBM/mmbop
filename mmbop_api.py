"""
Uses Falcon to implement simple API wrapper for mmbop
"""
import configparser
import hashlib
import falcon
import mmbop

# This is to silence pylint because of incorrect 'no-member' warnings
HTTP_500 = getattr(falcon, 'HTTP_500', '500 Internal Server Error')
HTTP_400 = getattr(falcon, 'HTTP_400', '400 Bad Request')
HTTP_201 = getattr(falcon, 'HTTP_201', '201 Created')
UNAUTH = getattr(falcon, 'HTTPUnauthorized')
# However I do not feel like adding unnecessary class methods
# pylint: disable=too-few-public-methods

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
            self.get_token()
        if not self.__class__.AUTH_TOKEN:
            raise falcon.HTTPError(HTTP_500, 'Auth Error', 'Unable to find auth token')

    def get_token(self):
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
            raise UNAUTH('Auth token required', desc)
        if not self._token_is_valid(token):
            desc = ('Invalid authentication token')
            raise UNAUTH('Invalid auth token', desc)

    def _token_is_valid(self, token):
        return bool(self._hash(token) == self.__class__.AUTH_TOKEN)

    @staticmethod
    def _hash(token):
        """
        Perform SHA224 hash on given token and return string (hexdigest)
        """
        return hashlib.sha224(str.encode(token)).hexdigest()

class RNDCBase(object):
    """
    Base API class to initialize rndc
    """

    def __init__(self, rndc_instance):
        self.rndc = rndc_instance

class NSBase(object):
    """
    Base API class to initialize nsupdate
    """

    def __init__(self, nsupdate_instance):
        self.nsupdate = nsupdate_instance

class DIGBase(object):
    """
    Base API class to initialize dig
    """

    def __init__(self, dig_instance):
        self.dig = dig_instance

class Query(DIGBase):
    """
    Handle query requests
    """

    def on_get(self, _, resp, entry):
        """
        Equivalent to "mmbop query <entry>" command
        """
        resp.body = (self.dig.find_record(entry))

class Status(RNDCBase):
    """
    Handle status requests
    """

    def on_get(self, _, resp):
        """
        Return result of 'rndc status' on GET request
        """
        resp.body = (self.rndc.status())

class HostModify(NSBase):
    """
    Handle hostmodify requests
    """

    def on_post(self, req, resp):
        """
        Equivalent to "mmbop.py hostadd <fqdn> <ip_addr>" command
        """
        fqdn = req.media.get('fqdn')
        addr = req.media.get('addr')
        force = req.media.get('force', False)
        if not (fqdn and addr):
            resp.status = HTTP_400
            resp.body = ('Need to provide the fqdn and addr in request')
        else:
            (success, message) = self.nsupdate.add_record(fqdn, addr, force)
            if success:
                resp.status = HTTP_201
                # call dig query and return that
                resp.body = (message)
            else:
                resp.status = HTTP_400
                resp.body = (message)

    def on_delete(self, req, resp):
        """
        Equivalent to "mmbop.py hostdel <entry>" command
        """
        entry = req.media.get('entry')
        force = req.media.get('force', False)
        if not entry:
            resp.status = HTTP_400
            resp.body = ('Need to provide the entry (fqdn or addr) to delete')
        else:
            (success, message) = self.nsupdate.delete_record(entry, force)
            if success:
                resp.body = (message)
            else:
                resp.status = HTTP_400
                resp.body = (message)

class HostList(DIGBase):
    """
    Handle hostlist requests
    """

    def on_get(self, _, resp, domain):
        """
        Equivalent to 'mmbop.py hostlist <domain>'
        """
        resp.body = (self.dig.hostlist(domain))

class HostSearch(DIGBase):
    """
    Handle hostsearch requests
    """

    def on_get(self, _, resp, domain, term):
        """
        Equivalent to 'mmbop.py hostlist <domain> <term>'
        Note that prepending '!' to the search term will enable
        negation - returning all entries that do not match the
        search term.
        """
        reverse = False
        if term.beginswith('!'):
            reverse = True
        resp.body = (self.dig.hostlist(domain, term, reverse))

class ZoneInfo(RNDCBase):
    """
    Handle status request for specific domain
    """

    def on_get(self, _, resp, domain):
        """
        Return result of 'rndc zoneinfo <zone>' on GET request
        """
        resp.body = (self.rndc.zonestatus(domain))

class ZoneList(RNDCBase):
    """
    Handle list of active zones
    """

    def on_get(self, _, resp):
        """
        Return result of 'rndc dumpdb' with zone checking
        """
        resp.body = (self.rndc.list_zones())

class ZoneModify(RNDCBase):
    """
    Handle add/delete requests
    """

    def on_post(self, req, resp):
        """
        Adding a zone via POST request
        """
        zone_name = req.media.get('domain')
        if not zone_name:
            resp.status = HTTP_400
            resp.body = ('Missing domain parameter')
        else:
            (success, message) = self.rndc.add(zone_name)
            if success:
                resp.status = HTTP_201
                resp.location = self.rndc.zonestatus(zone_name)
                resp.body = (message)
            else:
                resp.status = HTTP_400
                resp.body = (message)

    def on_delete(self, req, resp):
        """
        Removing a zone via DELETE request
        """
        zone_name = req.media.get('domain')
        if not zone_name:
            resp.statuss = HTTP_400
            resp.body = ('Missing domain parameter')
        else:
            (success, message) = self.rndc.delete(zone_name)
            if success:
                resp.body = (message)
            else:
                resp.status = HTTP_400
                resp.body = (message)


CONF_FILE = './mmbop.ini'

MY_CONF = mmbop.read_config(CONF_FILE)
MY_RNDC = mmbop.RNDC.create(**MY_CONF)
MY_NSUPDATE = MY_RNDC.my_nsupdate
MY_DIG = mmbop.DigQuery()
APP = falcon.API(middleware=[AuthToken()])
QUERY = Query(MY_DIG)
STATUS = Status(MY_RNDC)
HOSTMODIFY = HostModify(MY_NSUPDATE)
HOSTLIST = HostList(MY_DIG)
HOSTSEARCH = HostSearch(MY_DIG)
ZONEINFO = ZoneInfo(MY_RNDC)
ZONEMODIFY = ZoneModify(MY_RNDC)
ZONELIST = ZoneList(MY_RNDC)
APP.add_route('/query/{entry}', QUERY)
APP.add_route('/status', STATUS)
APP.add_route('/hostmodify', HOSTMODIFY)
APP.add_route('/hostlist/{domain}', HOSTLIST)
APP.add_route('/hostsearch/{domain}/{term}', HOSTSEARCH)
APP.add_route('/zonemodify', ZONEMODIFY)
APP.add_route('/zonelist', ZONELIST)
APP.add_route('/zoneinfo/{domain}', ZONEINFO)
