"""
Uses Falcon to implement simple API wrapper for mmbop
"""
import configparser
import hashlib
import json
import falcon
import mmbop

# Pylint really doesn't like falcon, this is to silence false positives
# pylint: disable=too-few-public-methods,c-extension-no-member,no-self-use,no-member

class HandleCORS(object):
    """
    To enable all sites to reach the API, as it relies on
    token authentication for access control
    """

    def process_request(self, req, resp):
        """
        Taken from:
        https://github.com/falconry/falcon/issues/1220
        """
        resp.set_header('Access-Control-Allow-Origin', '*')
        resp.set_header('Access-Control-Allow-Methods', '*')
        resp.set_header('Access-Control-Allow-Headers', '*')
        resp.set_header('Access-Control-Max-Age', 1728000)  # 20 days
        if req.method == 'OPTIONS':
            raise falcon.http_status.HTTPStatus(falcon.HTTP_200, body='\n')

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
            raise falcon.HTTPError(falcon.HTTP_500, 'Auth Error', 'Unable to find auth token')

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

    def on_get(self, req, resp):
        """
        Equivalent to "mmbop query <entry>" command
        """
        entry = req.params.get('entry', None)
        reply = []
        matched_entries = []
        if entry:
            matched_entries = self.dig.find_record(entry)
        if not matched_entries:
            reply.append({'entry': 'Record not found'})
        for match in matched_entries:
            try:
                (host, ttl, _, class_type, value) = match.split()
                reply.append({'entry': host, 'ttl': ttl,
                              'class': class_type, 'value': value})
            except ValueError:
                continue
        resp.body = json.dumps({'matched_entries': reply})

class Status(RNDCBase):
    """
    Handle status requests
    """

    def on_get(self, _, resp):
        """
        Return result of 'rndc status' on GET request
        Reply json:
            { 'server_status': [{ 'line': <line1>},
                                { 'line': <line2>},
                                ...
                               ]
            }
        """
        server_status = self.rndc.status()
        response_lines = [{'line': x} for x in server_status.split('\n')]
        resp.body = json.dumps({'server_status': response_lines})

class AliasAdd(NSBase):
    """
    Handle alias requests

    Returns JSON of form:
    {'results': [{ 'success': boolean, 'message': string }]}

    HTTP response code will be 201 (on adds) if result succeeded.
    Otherwise, response code will be 400.
    """

    def on_post(self, req, resp):
        """
        Equivalent to "mmbop.py alias <alias> <real>" command
        """
        result_list = []
        alias = req.media.get('alias')
        real = req.media.get('real')
        force = req.media.get('force', False)
        if not (alias and real):
            result_list.append({'success': False,
                                'message': 'Need to provide the alias and real name'})
        (success, message) = self.nsupdate.add_alias(alias, real, force)
        if success:
            message = alias + ' ' + real + ' added successfully'
            result_list.append({'success': True, 'message': message})
        else:
            message = alias + ' ' + real + ' not added: ' + message
            result_list.append({'success': False, 'message': message})
        if result_list[0]['success']:
            resp.status = falcon.HTTP_201
        else:
            resp.status = falcon.HTTP_400
        resp.body = json.dumps({'result': result_list})

class HostModify(NSBase):
    """
    Handle hostmodify requests

    Returns JSON of form:
    {'results': [{ 'success': boolean, 'message': string },
                 { 'success': boolean, 'message': string },
                 ...
                ]
    HTTP response code will be 201 (on adds) or 200 (on deletes)
    if all results succeeded. Otherwise, will be 400.
    """

    @staticmethod
    def _all_succeeded(results, delete=False):
        """
        Sets the response status code. If all transactions were
        successful, the response code will be 201 (for add) or
        200 (for delete). Otherwise, response code will be 400.
        """
        for result in results:
            if not result['success']:
                return falcon.HTTP_400
        if delete:
            return falcon.HTTP_200
        return falcon.HTTP_201

    def on_post(self, req, resp):
        """
        Equivalent to "mmbop.py hostadd <fqdn> <ip_addr> ..." command
        """
        result_list = []
        fqdn = req.media.get('fqdn')
        addr = req.media.get('addr')
        force = req.media.get('force', False)
        if not (fqdn and addr):
            result_list.append({'success': False,
                                'message': 'Need to provide the fqdn and addr'})
        else:
            if ' ' in addr:
                addr = addr.split(' ')
            (success, message) = self.nsupdate.add_record(fqdn, addr, force)
            if success:
                message = fqdn + ' ' + str(addr) + ' added successfully'
                result_list.append({'success': True, 'message': message})
            else:
                message = fqdn + ' ' + str(addr) + ' not added: ' + message
                result_list.append({'success': False, 'message': message})
        resp.status = self._all_succeeded(result_list)
        resp.body = json.dumps({'result': result_list})

    def on_delete(self, req, resp):
        """
        Equivalent to "mmbop.py hostdel <entry>" command
        """
        result_list = []
        entry = req.media.get('entry')
        force = req.media.get('force', False)
        if not entry:
            result_list.append({'success': False,
                                'message': 'Need to provide the fqdn or address'})
        else:
            (success, message) = self.nsupdate.delete_record(entry, force)
            if success:
                message = entry + ' deleted successfully'
                result_list.append({'success': True, 'message': message})
            else:
                message = entry + ' not deleted: ' + message
                result_list.append({'success': False, 'message': message})
        resp.status = self._all_succeeded(result_list)
        resp.body = json.dumps({'result': result_list})

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

    def on_get(self, req, resp):
        """
        Equivalent to 'mmbop.py hostlist <domain> <term>'.
        Call with query parameters: ?domain=xxx&term=yyy.
        Prepending '~' to the term will enable negation -
        returning all entries that do not match the term.
        Reply json:
            {matched_entries: [{entry: <entry1>, value: <value1>},
                               {entry: <entry2>, value: <value2>},
                               ...
                              ]
            }
        """
        reverse = False
        domain = req.params.get('domain', None)
        term = req.params.get('term', None)
        search_term = term
        matched_entries = []
        reply = []
        if term and term.startswith('~'):
            reverse = True
            search_term = term[1:]
        if domain:
            matched_entries = self.dig.search_domain(domain, search_term, reverse)
        if not matched_entries:
            message = 'No records found'
            if reverse:
                message = message + ' not'
            if term:
                message = message + ' containing term "' + search_term + '"'
            reply.append({'entry': message, 'value': None})
            matched_entries = [message]
        for match in matched_entries:
            try:
                (entry, _, _, _, value) = match.split()
                reply.append({'entry': entry, 'value': value})
            except ValueError:
                continue
        resp.body = json.dumps({'matched_entries': reply})

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
        Reply json:
            {zones: [{zone: <zone1>},
                     {zone: <zone2>},
                     ...
            }
        """
        zones = []
        zone_list = self.rndc.list_zones()
        for zone in zone_list:
            zones.append({'zone': zone})
        resp.body = json.dumps({'zones': zones})

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
MY_NSUPDATE = MY_RNDC.my_nsupdate
MY_DIG = mmbop.DigQuery()
APP = falcon.API(middleware=[HandleCORS(), AuthToken()])
QUERY = Query(MY_DIG)
STATUS = Status(MY_RNDC)
HOSTMODIFY = HostModify(MY_NSUPDATE)
ALIASADD = AliasAdd(MY_NSUPDATE)
HOSTLIST = HostList(MY_DIG)
HOSTSEARCH = HostSearch(MY_DIG)
ZONEINFO = ZoneInfo(MY_RNDC)
ZONEMODIFY = ZoneModify(MY_RNDC)
ZONELIST = ZoneList(MY_RNDC)
APP.add_route('/query', QUERY)
APP.add_route('/status', STATUS)
APP.add_route('/hostmodify', HOSTMODIFY)
APP.add_route('/alias', ALIASADD)
APP.add_route('/hostlist/{domain}', HOSTLIST)
APP.add_route('/hostsearch', HOSTSEARCH)
APP.add_route('/zonemodify', ZONEMODIFY)
APP.add_route('/zonelist', ZONELIST)
APP.add_route('/zoneinfo/{domain}', ZONEINFO)
