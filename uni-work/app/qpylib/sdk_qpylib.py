#!/usr/bin/python

# (C) Copyright IBM Corp. 2015, 2016
# The source code for this program is not published or
# otherwise divested of its trade secrets, irrespective of
# what has been deposited with the US Copyright Office.

from abstract_qpylib import AbstractQpylib
import json
import os
import os.path
import sys
import getpass
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import ssl
import unicodedata
import collections

dev_auth_file = ".qradar_appfw.auth"
dev_console_file = ".qradar_appfw.console"
dev_console_cert_file = ".qradar_appfw.console_cert"
yes = ("y", "yes")
no = ("no", "n")

api_auth_user = 0
api_auth_password = 0
consoleIP = 0
handler_added = 0

manifest_location = 'manifest.json'

class SdkQpylib(AbstractQpylib):

    def get_manifest_location(self):
        global manifest_location
        return manifest_location

    def get_app_id(self):
        return "DEV_APP"

    def get_app_name(self):
        return "SDK_APP"

    def get_cert_file(self, address, do_not_use_local_ca_bundle=False):
        global dev_console_cert_file
        home = os.path.expanduser("~")
        console_cert_file_path = os.path.join(home, dev_console_cert_file + "." + address + ".pem")
        if os.path.isfile(console_cert_file_path+".ignore"):
            return True
        if os.path.isfile(console_cert_file_path):
            print("Using console cert from file: " + str(console_cert_file_path))
            sys.stdout.flush()
            console_filepath = console_cert_file_path
        else:
            console_filepath = self.get_cert_from(address, console_cert_file_path, do_not_use_local_ca_bundle)
        return console_filepath

    def get_cert_from(self, address, console_cert_file_path, do_not_use_local_ca_bundle):
        verification = console_cert_file_path
        pem_data = ssl.get_server_certificate((address, 443))
        pem_text = unicodedata.normalize('NFKD', pem_data).encode('ascii', 'ignore')

        cert = x509.load_pem_x509_certificate(pem_text, default_backend())
 
        # If the issuer and the subject are the same then this is a self issued cert
        # and we need to handle it
        issuer = self.get_pem_issuer_name(cert)
        subject = self.get_pem_subject_name(cert)

        if issuer != subject:
            print 'Server PEM cert is not self issued'
            if do_not_use_local_ca_bundle:
                print 'It looks like we can not verify this cert against your local CA bundle'
            else:
                print 'We will try to use your local CA bundle to verify this server'
                return True
            
        print ''
        print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
        print 'This server ' + address + ' is unknown, do you want to trust it?'
        print '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
        print ''
        self.display_pem_cert_details(cert)
        print("Do you trust this certificate [y/n]:")
        sys.stdout.flush()
        do_store = raw_input()
        if do_store in yes:
            print("Storing cert file to " + console_cert_file_path)
            with open( console_cert_file_path, 'w' ) as cert_file:
                cert_file.write( pem_data )
        else:
            print("Not storing cert file for " + address )
            print("If you want to always drop back to CA certification for host then create a file called: " )
            print(console_cert_file_path + ".ignore")
            sys.exit()
        sys.stdout.flush()
 
        return verification

    def int_to_delim_hex(self, delim, num):
        line = '%x' % num
        array_line = [line[i:i+2] for i in range(0, len(line), 2)]
        return delim.join(array_line)

    _name_fields = [
                 'OID_COMMON_NAME',
                 'OID_COUNTRY_NAME',
                 'OID_DOMAIN_COMPONENT',
                 'OID_DN_QUALIFIER',
                 'OID_EMAIL_ADDRESS',
                 'OID_GENERATION_QUALIFIER',
                 'OID_GIVEN_NAME',
                 'OID_LOCALITY_NAME',
                 'OID_ORGANIZATIONAL_UNIT_NAME',
                 'OID_ORGANIZATION_NAME',
                 'OID_PSEUDONYM',
                 'OID_SERIAL_NUMBER',
                 'OID_STATE_OR_PROVINCE_NAME',
                 'OID_SURNAME',
                 'OID_TITLE'
              ]

    def display_pem_cert_details(self, pem_cert):
        print ('********************')
        print ('Certificate details:')
        print ('********************')
        print ('Version: {}'.format(pem_cert.version) )
        print 'SHA-256 Fingerprint: ',
        print ( ":".join("%02x" % ord(b) for b in pem_cert.fingerprint(hashes.SHA256() ) ) )
        print 'SHA1 Fingerprint: ',
        print ( ":".join("%02x" % ord(b) for b in pem_cert.fingerprint(hashes.SHA1() ) ) )
        print 'Serial Number: {}'.format( self.int_to_delim_hex(':', pem_cert.serial_number) )
        print 'Not valid before: {}'.format(pem_cert.not_valid_before)
        print 'Not valid after: {}'.format(pem_cert.not_valid_after)

        print 'Issuer:'
        for attr in self._name_fields:
            oid = getattr(x509, attr.upper())
            issuer = pem_cert.issuer
            info = issuer.get_attributes_for_oid(oid)
            if ( info ):
                print("    {}: {}".format(attr, info[0].value))

        print 'Subject:'
        for attr in self._name_fields:
            oid = getattr(x509, attr.upper())
            subject = pem_cert.subject
            info = subject.get_attributes_for_oid(oid)
            if ( info ):
                print("    {}: {}".format(attr, info[0].value))

        print 'Signature Hash Algorithm: {}'.format(pem_cert.signature_algorithm_oid._name)

        for ext in pem_cert.extensions:
            try:
                print 'Extension: Name :', ext.oid._name
                print '    Critical :', ext.critical
                if isinstance ( ext.value, collections.Iterable):
                    for extsub in ext.value:
                        print '    Value :', str(extsub)
                else:
                    print '    Value :', ext.value
            except UnicodeEncodeError:
                pass

        print 'Signature: '
        print ( ":".join("%02x" % ord(b) for b in pem_cert.signature ) )
        print 'TBS Cert Signature: '
        print ( ":".join("%02x" % ord(b) for b in pem_cert.tbs_certificate_bytes ) )



    def get_console_address(self):
        global consoleIP
        global dev_console_file
        home = os.path.expanduser("~")
        console_file_path = os.path.join(home, dev_console_file)
        if os.path.isfile(console_file_path):
            print("Loading console details from file: " + str(console_file_path))
            sys.stdout.flush()
            with open(console_file_path) as consolefile:
                console_json = json.load(consolefile)
            consoleIP = console_json["console"]
        else:
            if consoleIP == 0:
                console_data = {}
                print("What is the IP of QRadar console"),
                print("required to make this API call:")
                sys.stdout.flush()
                consoleIP = raw_input()
                console_data['console'] = consoleIP
                print("Do you want to store the console IP at:" + console_file_path)
                print("[y/n]:")
                sys.stdout.flush()
                do_store = raw_input()
                if do_store in yes:
                    with open(console_file_path, 'w+') as console_file:
                        json.dump(console_data, console_file)
        return consoleIP

    def get_api_auth(self):
        auth = None
        global dev_auth_file
        global api_auth_user
        global api_auth_password
        home = os.path.expanduser("~")
        auth_file_path = os.path.join(home, dev_auth_file)
        if os.path.isfile(auth_file_path):
            print("Loading user details from file: " + str(auth_file_path))
            sys.stdout.flush()
            with open(auth_file_path) as authfile:
                auth_json = json.load(authfile)
                auth = (auth_json["user"], auth_json["password"])
        else:
            auth_data = {}
            consoleAddress = self.get_console_address()
            print("QRadar credentials for " + consoleAddress + " are required to make this API call:")
            if api_auth_user == 0:
                print( "User:" )
                sys.stdout.flush()
                api_auth_user = raw_input()
            if api_auth_password == 0:
                api_auth_password = getpass.getpass("Password:")
                auth_data['user'] = api_auth_user
                auth_data['password'] = api_auth_password
                print("Store credentials credentials at:" + auth_file_path)
                print("WARNING: credentials will be stored in clear.")
                print("[y/n]:")
                sys.stdout.flush()
                do_store = raw_input()
                if do_store in yes:
                    with open(auth_file_path, 'w+') as auth_file:
                        json.dump(auth_data, auth_file)
            auth = (api_auth_user, api_auth_password)
        print( "Using Auth: " + str(auth) )
        return auth


    def REST(self, RESTtype, requestURL, headers=None, data=None, params=None,
             json_inst=None, version=None, verify=True, timeout=60):
        if headers is None:
            headers={}
        if version is not None:
            headers['Version'] = version
        auth = self.get_api_auth()
        consoleAddress = self.get_console_address()
        fullURL = "https://" + str(consoleAddress()) + "/" + str(requestURL)
        rest_func = self.chooseREST(RESTtype)
        if verify is not None:
            verify = self.get_cert_file(consoleAddress)
        return rest_func(URL=fullURL, headers=headers, data=data, auth=auth, params=params, json_inst=json_inst, timeout=timeout, verify=verify)

    def add_log_handler(self, loc_logger):
        global handler_added
        if 0 == handler_added:
            loc_logger.setLevel(self.map_log_level('debug'))
            handler = logging.StreamHandler()
            loc_logger.addHandler(handler)
            handler_added=1

    def root_path(self):
        return os.getenv('QRADAR_APPFW_WORKSPACE', '~')

    def get_app_base_url(self):
        return "http://localhost:5000"
