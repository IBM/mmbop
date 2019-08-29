#!/usr/local/bin/python3.7
"""

mmbop.py

mmbop manages BIND over Python

While entries in a zone file can be managed using Dynamic DNS, the creation and removal
of zones has to be done through editing the named.conf file or with rndc.

However rndc itself requires that the template zone file already exists, which necessitates
some kind of helper/wrapper function so that the creation (and removal) of zones
can be performed in an atomic manner. This script performs that function.

This also supports the use of catalog zones, so that (through nsupdate) the catalog zone
can be modified and the secondary servers will serve the new zones automatically.

An attempt was made to rely only on Python standard library modules (which is why
nsupdate is used, instead of dnspython, to update the catalog zone).

The script can run directly or as a REST API service (with the -r <port> flag)

Author: Scott Strattner (sstrattn@us.ibm.com)

"""

import argparse
import configparser
import grp
import hashlib
import logging
import os
import pwd
import re
import sys
import subprocess
from time import sleep

class NSUpdateError(Exception):
    """
    Error class for NSUpdate
    """
    pass

class NSUpdate(object):
    """
    Handles communication with nsupdate
    """

    CATALOG = 'zone {czone}\n'
    CATALOG += 'update {action} {hname}.zones.{czone} 3600 IN PTR {zname}.\n'
    CATALOG += 'send\n'
    TEMP_DIR = '/tmp'

    def __init__(self, path='/usr/bin/nsupdate', key=None):
        """
        Raise NSUpdateError if the path to nsupdate is invalid
        """
        if os.path.exists(path) and os.path.isfile(path):
            # set nsupdate to always use TCP and enforce local mode
            self.command = [path, '-v', '-l']
            if key:
                self.command.extend(['-k', key])
        else:
            raise NSUpdateError('Invalid path %s' % path)

    def call(self, catalog_zone, domain, action='add'):
        """
        Call nsupdate to modify the catalog zone
        """
        nsupdate_form = self.format_catalog(catalog_zone, domain, action)
        reply = subprocess.run(self.command, encoding='utf-8', input=nsupdate_form,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if reply.returncode == 0:
            logging.debug('nsupdate completed successfully: %s', reply.stdout)
            return (True, None)
        logging.debug('nsupdate failed: %s', reply.stderr)
        return (False, reply.stderr)

    def add(self, catalog_zone, domain_to_add):
        """
        Add the specified domain to catalog
        """
        return self.call(catalog_zone, domain_to_add)

    def delete(self, catalog_zone, domain_to_remove):
        """
        Remove the specified domain from catalog
        """
        action = 'delete'
        return self.call(catalog_zone, domain_to_remove, action)


    @staticmethod
    def hex_digest_format(domain_name):
        """
        Given a domain name, return the BIND wire format SHA1 hex digit
        of the name
        """
        if not domain_name.endswith('.'):
            domain_name += '.'
        zone_labels = domain_name.split('.')
        digest_labels = [chr(len(x)) + x for x in zone_labels]
        byte_labels = [x.encode() for x in digest_labels]
        byte_string = b''.join(byte_labels)
        return hashlib.sha1(byte_string).hexdigest()

    def format_catalog(self, catalog_zone, domain_to_add, action):
        """
        Fill out the nsupdate format for modifying the catalog zone
        """
        hashed_name = self.hex_digest_format(domain_to_add)
        catalog_form = self.CATALOG.format(czone=catalog_zone, hname=hashed_name,
                                           zname=domain_to_add, action=action)
        logging.debug('Nsupdate update file contents: %s', catalog_form)
        return catalog_form

class RNDCError(Exception):
    """
    Error class for RNDC
    """
    pass

class RNDC(object):
    """
    Handles communication with rndc
    """

    # Template for creating new zone file
    # Adapted from example here: https://en.wikipedia.org/wiki/Zone_file
    # Adjust the various timeout values to suit your environment
    SKELETON_ZONE = '$ORIGIN {zone}.\n$TTL 1h\n'
    SKELETON_ZONE += '{zone}. IN SOA {ns1}. {owner}. ( {serial} 1d 2h 4w 1h )\n'
    SKELETON_ZONE += '{zone}. IN NS {ns1}.\n{zone}. IN NS {ns2}.\n'

    @classmethod
    def create(cls, **kwargs):
        """
        Return an RNDC instance, only if it is valid (can make a successful
        'rndc status' call), raise RNDCError otherwise.
        """
        rndc_instance = cls(**kwargs)
        if rndc_instance.status(True):
            return rndc_instance
        raise RNDCError('Cannot communicate with BIND using rndc')

    def __init__(self, **kwargs):
        """
        arguments that are used (and their default value if not specified):

            key:      The location of the rndc key file (/etc/bind/rndc.key)
            server:   The IP of the DNS server rndc can connect to (127.0.0.1)
            port:     The TCP port that rndc service runs on (953)
            path:     The full path to rndc executable (/usr/sbin/rndc)
            dns1:     The name of the primary DNS server (ns1.example.com)
            dns2:     The name of the secondary DNS server (ns2.example.com)
            serial:   The starting serial number for a new zone (1)
            view:     The view in named.conf where zones are located (None)
            owner:    SOA contact for the zone (hostmaster.example.com)
            protect:  List of domains that cannot be managed ([])
            require:  List of substrings, one of which domain should match ([])
            namedir:  Directory location for zone files (/etc/bind/)
            nameown:  File owner for zone files (bind)
            namegrp:  Group owner for zone files (bind)
            nameper:  File permissions mask for zone files (0644)
            options:  List of statements to add to zone definition ([])

        Note that the default values for some arguments will probably
        not work in your environment, and so should be specified when
        calling this function (ie, added to the mmbop.ini configuration)
        or modify the 'get' statements below to set fallback values
        """
        self.info = {}
        keyfile = kwargs.get('keyfile', '/etc/bind/rndc.key')
        server = kwargs.get('server', '127.0.0.1')
        port = str(kwargs.get('port', 953))
        path = kwargs.get('path', '/usr/sbin/rndc')
        dns1 = kwargs.get('dns1', 'ns1.example.com')
        dns2 = kwargs.get('dns2', 'ns2.example.com')
        serial = str(kwargs.get('serial', 1))
        view = kwargs.get('view', None)
        owner = kwargs.get('owner', 'hostmaster.example.com')
        protect = kwargs.get('protect', [])
        require = kwargs.get('require', [])
        namedir = kwargs.get('namedir', '/etc/bind/')
        nameown = kwargs.get('nameown', 'bind')
        namegrp = kwargs.get('namegrp', 'bind')
        nameper = kwargs.get('nameper', '0644')
        options = kwargs.get('options', [])
        catalog = kwargs.get('catalog', None)
        if not namedir.endswith('/'):
            namedir += '/'
        if os.path.exists(path) and os.path.isfile(path):
            self.info['exec'] = path
        else:
            raise RNDCError('Invalid path to rndc: %s' % path)
        if os.path.exists(keyfile) and os.path.isfile(keyfile):
            self.info['key'] = keyfile
            self.info['server'] = server
            self.info['port'] = port
        else:
            raise RNDCError('Key file %s not found or invalid' % keyfile)
        self.info['dns'] = [dns1, dns2]
        self.info['serial'] = serial
        self.info['view'] = view
        self.info['owner'] = owner
        if isinstance(protect, str):
            self.info['protect'] = [protect]
        else:
            self.info['protect'] = protect
        if isinstance(require, str):
            self.info['require'] = [require]
        else:
            self.info['require'] = require
        self.info['namedir'] = namedir
        self.info['nameown'] = nameown
        self.info['namegrp'] = namegrp
        try:
            self.info['nameper'] = int(nameper, base=8)
        except ValueError:
            self.info['nameper'] = 0o644  # Octal format for Python3
        if isinstance(options, str):
            self.info['options'] = [options]
        else:
            self.info['options'] = options
        self.info['catalog'] = catalog

    def call(self, rndc_command):
        """
        Use subprocess.run to make call to rndc, return result as
        a CompletedProcess instance.
        """
        command = [self.info['exec']]
        command.extend(['-k', self.info['key'], '-s', self.info['server']])
        command.extend(['-p', self.info['port']])
        if isinstance(rndc_command, list):
            command.extend(rndc_command)
        elif isinstance(rndc_command, str):
            command.append(rndc_command)
        logging.debug('Calling rndc with following options: %s', command)
        return subprocess.run(command, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True)


    def status(self, check_conn_only=False):
        """
        Return result of 'rndc status' command.
        If check_conn_only, return boolean if the connection was successful
        or not.
        """
        status_response = self.call('status')
        if status_response.returncode == 0:
            if check_conn_only:
                return True
            return status_response.stdout
        return status_response.stderr

    def zonestatus(self, zone_name):
        """
        Return result of 'rndc zonestatus <zone>' command.
        """
        status_response = self.call(['zonestatus', zone_name])
        if status_response.returncode == 0:
            return status_response.stdout
        return status_response.stderr

    @staticmethod
    def _dump_file_is_ready(dump_file):
        """
        Looks for last line of named dump file, indicating completion
        """
        end_of_file = '; Dump complete'
        last_line = os.popen('tail -1 ' + dump_file).read().rstrip()
        if last_line == end_of_file:
            return True
        return False

    def list_zones(self):
        """
        Perform an rndc dumpdb, parse for zones matching required
        stanzas, return list of those zones
        """
        zone_list = []
        zone_info = []
        zone_line_match = r"Zone dump of '(\S+)\/IN"
        dump_file = self.info['namedir'] + 'named_dump.db'
        dump_response = self.call(['dumpdb', '-zones'])
        if dump_response.returncode != 0:
            logging.debug('Unable to create dump file. Cannot get list of zones.')
            return None
        sleep_counter = 0
        while not self._dump_file_is_ready(dump_file):
            sleep_counter += 1
            sleep(1)
            if sleep_counter > 10:
                logging.debug('Issue waiting on dump file to complete')
                return None
        try:
            logging.debug('Attempting to view dump file %s', dump_file)
            with open(dump_file) as bind_dump:
                for line in bind_dump:
                    line = line.strip()
                    if line.startswith(';'):
                        zone_info.append(line)
        except OSError as os_err:
            logging.debug('Cannot read dump file: %s', os_err)
            return None
        for entry in zone_info:
            matcher = re.search(zone_line_match, entry)
            if matcher:
                if self.zone_is_valid(matcher.group(1)):
                    logging.debug('Found zone %s', matcher.group(1))
                    zone_list.append(matcher.group(1))
        logging.debug('Found zones: %s', zone_list)
        return " ".join(zone_list)


    def add(self, zone_name):
        """
        Add the requested zone
        Returns a tuple of form: (boolean, string)
        If the add was successful, boolean is True and string is rndc stdout (probably empty)
        If the add failed, boolean is False and string is rndc stderr
        """
        if not self.zone_is_valid(zone_name):
            return (False, 'Not a valid zone name. Check configuration.')
        empty_zone_file = self.SKELETON_ZONE.format(zone=zone_name, ns1=self.info['dns'][0],
                                                    ns2=self.info['dns'][1],
                                                    owner=self.info['owner'],
                                                    serial=self.info['serial'])
        file_name = self.write_zone_file(zone_name, empty_zone_file)
        if not file_name:
            return (False, 'Unable to place zone file in named directory. Check permissions.')
        add_commands = 'addzone ' + zone_name + ' '
        if self.info['view']:
            add_commands += 'IN ' + self.info['view'] + ' '
        add_commands += ' { type master; file "' + file_name + '"; '
        for opt_line in self.info['options']:
            add_commands += opt_line + ' '
        add_commands += "};"
        logging.debug('rndc command: %s', add_commands)
        add_response = self.call([add_commands])
        if add_response.returncode == 0:
            logging.debug('Zone %s added successfully', zone_name)
            if self.info['catalog']:
                (success, message) = self.add_to_catalog(zone_name)
                if success:
                    return (True, '%s zone and catalog file added successfully' % zone_name)
                return (False, '%s zone added but catalog add failed: %s' % (zone_name, message))
            return (True, add_response.stdout)
        logging.debug('Zone %s add failed: %s', zone_name, add_response.stderr)
        message_index = add_response.stderr.rfind(':') + 1
        error_message = add_response.stderr[message_index:].rstrip()
        return (False, error_message)

    def delete(self, zone_name):
        """
        Delete the requested zone
        Returns a tuple of form: (boolean, string)
        If the delete was successful, boolean is True and string is empty (or unimportant)
        If the delete failed, boolean is False and string holds error message

        A decision was made to return True if the zone file could not be removed,
        as that does not affect the DNS service (it is a housekeeping issue). The
        string message will indicate if that is the case.
        """
        if not self.zone_is_valid(zone_name):
            return (False, 'Not a valid zone name. Check configuration.')
        del_commands = 'delzone ' + zone_name
        del_response = self.call([del_commands])
        if del_response.returncode == 0:
            logging.debug('Zone %s removed successfully', zone_name)
            if self.info['catalog']:
                (success, message) = self.delete_from_catalog(zone_name)
                if success:
                    file_removal = self.delete_zone_file(zone_name)
                    if not file_removal:
                        return (True, '%s and catalog entry removed, unable to delete zone file'
                                % zone_name)
                    return (True, '%s and catalog entry removed successfully' % zone_name)
                return (False, '%s removed but catalog delete failed: %s' % (zone_name, message))
            return (True, del_response.stdout)
        logging.debug('Zone %s delete failed: %s', zone_name, del_response.stderr)
        message_index = del_response.stderr.rfind(':') + 1
        error_message = del_response.stderr[message_index:].rstrip()
        return (False, error_message)

    def add_to_catalog(self, zone_name):
        """
        Use nsupdate to modify the catalog zone file
        """
        my_nsupdate = NSUpdate(key=self.info['key'])
        return my_nsupdate.add(self.info['catalog'], zone_name)

    def delete_from_catalog(self, zone_name):
        """
        Use nsupdate to remove the domain from the catalog zone file
        """
        my_nsupdate = NSUpdate(key=self.info['key'])
        return my_nsupdate.delete(self.info['catalog'], zone_name)

    def write_zone_file(self, zone_name, zone_file):
        """
        Attempt to write file to named zone file directory, and
        set appropriate owner/group and read/write permissions.
        Return the name of the file if successfully written.
        """
        file_path = self.info['namedir'] + zone_name + '.db'
        try:
            uid = pwd.getpwnam(self.info['nameown']).pw_uid
            gid = grp.getgrnam(self.info['namegrp']).gr_gid
            with open(file_path, 'w') as z_file:
                z_file.write(zone_file)
            os.chown(file_path, uid, gid)
            os.chmod(file_path, self.info['nameper'])
        except (KeyError, OSError, IOError) as io_os_err:
            logging.debug('Error in writing zone file %s', io_os_err)
            return None
        #return file_path
        return zone_name + '.db'

    def delete_zone_file(self, zone_name):
        """
        Return boolean on success of zone file removal
        """
        file_path = self.info['namedir'] + zone_name + '.db'
        try:
            os.remove(file_path)
        except (OSError, IOError) as io_os_err:
            logging.debug('Error in deleting zone file %s: %s', file_path, io_os_err)
            return False
        return True

    def zone_is_valid(self, zone_name):
        """
        Returns True if zone is not part of protect list
        and meets at least one of the criteria of require
        list. Otherwise, returns False.
        """
        for protect_zone in self.info['protect']:
            logging.debug('Checking zone %s against protected zone %s', zone_name, protect_zone)
            if zone_name == protect_zone:
                logging.debug('Zone %s is protected. Ignoring request.', zone_name)
                return False
        for req_name in self.info['require']:
            logging.debug('Checking zone %s against required string %s', zone_name, req_name)
            if zone_name.endswith(req_name):
                logging.debug('Zone %s meets requirements and is valid', zone_name)
                return True
        logging.debug('Zone %s does not meet substring requirements. Ignoring request.', zone_name)
        return False

def read_config(conf_file='./mmbop.ini'):
    """
    Import the mmbop configuration file as a ConfigParser
    object and return it as a real dictionary
    """
    config = configparser.ConfigParser()
    try:
        config.read(conf_file)
        config = ensure_defaults(config)
        return config_to_dict(config)
    except IOError as io_err:
        logging.debug('Error reading config file: %s', io_err)
    return None

def ensure_defaults(config):
    """
    Make sure the required values (server, port, key) are
    specified in the ConfigParser object
    """
    default_section = 'RNDC'
    default_values = {'server': '127.0.0.1',
                      'port': '953',
                      'keyfile': '/etc/bind/rndc.key'}
    if not config.has_section(default_section):
        config.add_section(default_section)
    for req_key in default_values:
        if req_key not in config.options(default_section):
            config.set(default_section, req_key, default_values[req_key])
    logging.debug('Configuration: %s', print_config(config))
    return config

def config_to_dict(config_parser_obj):
    """
    While a ConfigParser object is close to a dictionary, it
    isn't one. This collapses the sections (flattens the keys)
    and converts it to a dictionary, while also converting
    multiple values into a list
    """
    conf_dict = {}
    for section in config_parser_obj.sections():
        for item in config_parser_obj.options(section):
            if item == 'https':
                item_value = config_parser_obj[section].getboolean(item)
            else:
                item_value = config_parser_obj[section][item]
                if '|' in item_value:
                    item_value = item_value.split('|')
            conf_dict[item] = item_value
    return conf_dict

def print_config(config_parser_obj):
    """
    Helper function to return all of the configuration
    values as a string, for debugging
    """
    conf_list = []
    for section in config_parser_obj.sections():
        for key in config_parser_obj[section]:
            conf_list.append(section + ':' + key + ':' + config_parser_obj[section][key])
    return " ".join(conf_list)

def parse_arguments():
    """
    Uses argparse to define and parse command-line arguments
    """
    help_width = lambda prog: argparse.HelpFormatter(prog, max_help_position=34)
    desc = 'mmbop manages BIND over Python'
    parser = argparse.ArgumentParser(description=desc, formatter_class=help_width)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose messages')
    parser.add_argument('-c', '--config', metavar='FILE', help='Location of mmbop config file',
                        default='./mmbop.ini')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-a', '--add', metavar='ZONE', help='Add specified zone')
    group.add_argument('-d', '--delete', metavar='ZONE', help='Delete specified zone')
    group.add_argument('-l', '--list', action='store_true', help='List all zones')
    group.add_argument('-s', '--status', action='store_true', help='Show status of DNS server')
    group.add_argument('-z', '--zonestatus', metavar='ZONE', help='Show status of specified zone')
    if len(sys.argv) == 1:    # No action is provided
        parser.print_help(sys.stderr)
        sys.exit(1)
    return parser.parse_args()

def set_logging(debug_flag=False):
    """
    Set logging to either DEBUG or INFO
    """
    if debug_flag:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

def main():
    """
    Direct calling function
    """
    my_args = parse_arguments()
    set_logging(my_args.verbose)
    my_conf = read_config(my_args.config)
    my_rndc = RNDC.create(**my_conf)
    if my_args.status:
        print(my_rndc.status())
    if my_args.zonestatus:
        print(my_rndc.zonestatus(my_args.zonestatus))
    if my_args.list:
        zones = my_rndc.list_zones()
        if not zones:
            print('Unable to get list of zones. Run debug for more info.')
            exit(1)
        zone_list = zones.split(' ')
        for zone in zone_list:
            print(zone)
    if my_args.add:
        (success, message) = my_rndc.add(my_args.add)
        if not success:
            print('Add of zone %s failed: %s' % (my_args.add, message))
        else:
            print('Zone %s added' % my_args.add)
    if my_args.delete:
        (success, message) = my_rndc.delete(my_args.delete)
        if not success:
            print('Deletion of zone %s failed: %s' % (my_args.delete, message))
        else:
            print('Zone %s deleted' % my_args.delete)


if __name__ == "__main__":
    main()
