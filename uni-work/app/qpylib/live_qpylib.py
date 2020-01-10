#!/usr/bin/python

# (C) Copyright IBM Corp. 2015, 2016
# The source code for this program is not published or
# otherwise divested of its trade secrets, irrespective of
# what has been deposited with the US Copyright Office.

from abstract_qpylib import AbstractQpylib
from logging.handlers import RotatingFileHandler, SysLogHandler
from logging import Formatter
from flask import request
from flask import has_request_context
import oauth_qpylib
import os
import socket

manifest_location = 'app/manifest.json'
logfile_location = '/store/log/app.log'
consolecert_location = '/store/consolecert.pem'

class LiveQpylib(AbstractQpylib):

    def get_manifest_location(self):
        global manifest_location
        return manifest_location

    def get_console_address(self):
        manifest = self.get_manifest_json()
        console_ip = ''
        if 'console_ip' not in manifest:
            self.log('console not defined in manifest - default to localhost',
                level='error')
            console_ip = '127.0.0.1'
        else:
            console_ip = manifest['console_ip']
        return console_ip

    def get_cert_file(self, address, do_not_use_local_ca_bundle=False):
        # Turning off local ca bundle does not make sense here
        # as this method will not return true
        # It is only done in SDK
        self.log('address ' + str(address), 'debug' )
        self.log('do_not_use_local_ca_bundle ' + str(do_not_use_local_ca_bundle), 'debug' )
        if os.path.isfile(consolecert_location):
            self.log('Using console cert from file: ' + str(consolecert_location),
                     level='debug')
            console_filepath = consolecert_location
        else:
            self.log('Unable to find cert file, validation turned off: ' +
                     str(consolecert_location), level='debug')
            console_filepath = False
        return console_filepath

    def acquire_SEC_token(self):
        return request.cookies.get('SEC')

    def acquire_QRadarCSRF_token(self):
        return request.cookies.get('QRadarCSRF')

    def get_tokens(self, headers, version=None):
        csrf_cookie = 'QRadarCSRF'
        sec_cookie = 'SEC'

        if headers is None:
            headers = {}

        if version is not None:
            headers['Version'] = version

        if headers.get('Host') is None:
            headers['Host'] = socket.gethostbyname(socket.gethostname())

        if has_request_context():
            if csrf_cookie in request.cookies.keys():
                headers[csrf_cookie] = self.acquire_QRadarCSRF_token()
            if sec_cookie in request.cookies.keys() \
                and sec_cookie not in headers.keys():
                headers[sec_cookie] = self.acquire_SEC_token()

        # Check if oauth can be used
        if self.is_manifest_oauth():
            oauth_qpylib.add_oauth_header(headers)

        return headers

    def get_manifest_log_level(self):
        log_level = 'info'
        manifest = self.get_manifest_json()
        if 'log_level' in manifest.keys():
            log_level = manifest["log_level"]
        return log_level

    def add_log_handler(self, loc_logger):
        global logfile_location
        loc_logger.setLevel(self.map_log_level(self.get_manifest_log_level()))
        handler = RotatingFileHandler(logfile_location, maxBytes=2*1024*1024, backupCount=5)
        handler.setFormatter(Formatter('%(asctime)s [%(module)s.%(funcName)s] [%(threadName)s] [%(levelname)s] - %(message)s'))
        loc_logger.addHandler(handler)

        console_ip = self.get_console_address()

        if console_ip.startswith('[') and console_ip.endswith(']'):
            # Ipv6 address - Strip [] for syslog
            console_ip = console_ip[1:-1]

        syslogHandler = SysLogHandler(address=(
                                     socket.gethostbyname(socket.gethostname()), 514))
        syslogHandler.setFormatter(Formatter('%(asctime)s %(module)s.%(funcName)s: %(message)s'))
        loc_logger.addHandler(syslogHandler)
        return

    def REST(self, RESTtype, requestURL, headers=None, data=None,
             params=None, json_inst=None, version=None, verify=True,
             timeout=60):
        headers = self.get_tokens(headers, version)
        fullURL = "https://" + self.get_console_address() + "/" + requestURL

        if verify is not None:
            verify = self.get_cert_file(self.get_console_address())

        self.log("REST=" + fullURL +
                  " RESTtype=" + RESTtype +
                  " headers=" + str(headers) +
                  " data=" + str(data) +
                  " params=" + str(params) +
                  " json=" + str(json_inst) +
                  " verify=" + str(verify) +
                  " version=" + str(version), 'debug')
        response = self.chooseREST(RESTtype)(URL=fullURL, headers=headers, data=data,
                                             params=params, json_inst=json_inst,
                                             timeout=timeout, verify=verify)
        if self.is_manifest_oauth():
            if response.status_code == 401:
                self.log('oauth token not valid, get another')
                oauth_qpylib.add_oauth_header(headers, renew_token=True)
                response = self.chooseREST(RESTtype)(URL=fullURL, headers=headers, data=data,
                                                     params=params, json_inst=json_inst,
                                                     timeout=timeout, verify=verify)
                if response.status_code == 401:
                    raise ValueError('oauth token is not valid')
        return response

    def get_app_name(self):
        manifest = self.get_manifest_json()
        app_name = 'None'
        if 'name' in manifest.keys():
            app_name = str(manifest["name"])
        return app_name

    def get_app_id(self):
        manifest = self.get_manifest_json()
        app_id = '0'
        if 'app_id' in manifest.keys():
            app_id = str(manifest["app_id"])
        return app_id

    def get_app_base_url(self):
        """
        Get the full url through QRadar, that will proxy any request to the
        appropriate Application plugin servlet
        """
        self.log("getAppBaseUrl>>>", 'debug')

        # read /app/manifest.json
        # get 'console_ip' and 'app_id' fields
        # concat into url format:
        # https://{console_ip}/console/plugins/{<}app_id}/app_proxy
        console_ip = ''
        url_suffix = ''
        proxy_path = ''

        manifest = self.get_manifest_json()
        if 'console_ip' in manifest.keys():
            console_ip = str(manifest["console_ip"])
        if 'app_id' in manifest.keys():
            app_id = str(manifest["app_id"])
            url_suffix = "/console/plugins/" + app_id + "/app_proxy"

        if request.headers.get('X-Console-Host'):
            proxy_path = "https://" + request.headers['X-Console-Host'] + url_suffix
        # If any of the information required for building the proxy then no base proxy path is generated
        elif console_ip is not '' and url_suffix is not '':
            proxy_path = "https://" + console_ip + url_suffix

        self.log("proxy_path==>" + proxy_path, 'debug')
        self.log("<<<getAppBaseUrl", 'debug')
        return proxy_path

    def root_path(self):
        return "/"
