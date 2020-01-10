#!/usr/bin/python

# (C) Copyright IBM Corp. 2015, 2016
# The source code for this program is not published or
# otherwise divested of its trade secrets, irrespective of
# what has been deposited with the US Copyright Office.

from abc import ABCMeta, abstractmethod
import os
import requests
import logging
from flask import url_for
import offense_qpylib
import asset_qpylib
import json_qpylib
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

loggerName = 'com.ibm.applicationLogger'
logger = 0
cached_manifest = None

class HostNameIgnoringAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        #pylint: disable=attribute-defined-outside-init
        #We need to set self.poolmanager in this fashion
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       assert_hostname=False,
                                       **pool_kwargs)

class AbstractQpylib(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_app_id(self):
        pass

    @abstractmethod
    def get_app_name(self):
        pass

    @abstractmethod
    def get_manifest_location(self):
        pass

    def get_manifest_json(self):
        global cached_manifest
        if cached_manifest is None:
            full_manifest_location = os.path.join(self.root_path(), self.get_manifest_location())
            with open(full_manifest_location) as manifest_file:
                cached_manifest = json.load(manifest_file)
        return cached_manifest

    def is_manifest_oauth(self):
        manifest = self.get_manifest_json()
        return 'authentication' in manifest.keys()

    def add_transport_adapter(self, verify):
        s = requests.Session()
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509
            if isinstance(verify, basestring):
                with open(verify) as pem_file:
                    pem_text = pem_file.read()
                    pem = x509.load_pem_x509_certificate(pem_text, default_backend())

                    issuer = self.get_pem_issuer_name(pem)
                    subject = self.get_pem_subject_name(pem)

                    # If the issuer name and subject name are the
                    # same then this is a self issued cert and we
                    # need to handle it
                    if subject == issuer:
                        self.log("PEM cert from server is self issued", "debug")
                        s.mount('https://', HostNameIgnoringAdapter())
        except ImportError:
            self.log("Unable to verify remote QRadar server as no crypto installed in app")
        return s

    def RESTget(self, URL, headers, data=None,
                params=None, json_inst=None, auth=None,
                timeout=60, verify=True):
        self.log("REST get issued to " + URL + " " + str(params), "debug")
        s = self.add_transport_adapter(verify)
        return s.get(URL, params=params,
                            headers=headers, verify=verify, auth=auth,
                            data=data, json=json_inst, timeout=timeout)

    def RESTput(self, URL, headers, data=None,
                params=None, json_inst=None, auth=None,
                timeout=60, verify=True):
        self.log("REST put issued to " + URL + " " + str(params), "debug")
        s = self.add_transport_adapter(verify)
        return s.put(URL, params=params,
                            headers=headers, verify=verify, auth=auth,
                            data=data, json=json_inst, timeout=timeout)

    def RESTpost(self, URL, headers, data=None,
                 params=None, json_inst=None, auth=None,
                 timeout=60, verify=True):
        self.log("REST post issued to " + URL + " " + str(params), "debug")
        s = self.add_transport_adapter(verify)
        return s.post(URL, params=params,
                            headers=headers, verify=verify, auth=auth,
                            data=data, json=json_inst, timeout=timeout)

    def RESTdelete(self, URL, headers, data=None,
                   params=None, json_inst=None, auth=None,
                   timeout=None, verify=True):
        self.log("REST delete issued to " + URL + " " + str(params), "debug")
        s = self.add_transport_adapter(verify)
        return s.delete(URL, params=params,
                            headers=headers, verify=verify, auth=auth,
                            data=data, json=json_inst, timeout=timeout)

    def RESTunsupported(self, URL, headers, data=None,
                        params=None, json_inst=None, auth=None,
                        verify=True, timeout=0):
        self.log("REST unsupported issued to " + URL + " " + str(params) +
                 str(headers) + str(data) + str(json_inst) + str(auth) +
                 str(verify) + str(timeout), "debug")
        raise ValueError('The REST type passed is not supported')

    def chooseREST(self, RESTtype):
        RESTtype = RESTtype.upper()
        return {
            'GET': self.RESTget,
            'PUT': self.RESTput,
            'POST': self.RESTpost,
            'DELETE': self.RESTdelete,
        }.get(RESTtype, self.RESTunsupported)

    @abstractmethod
    def REST(self, RESTtype, requestURL, headers=None, data=None,
             params=None, json_inst=None, version=None, verify=True,
             timeout=60):
        pass

    def choose_log_level(self, level='INFO'):
        if logger == 0:
            raise SystemError('You can not call log before logging has been initialised')

        level = level.upper()
        return {
            'INFO': logger.info,
            'DEBUG': logger.debug,
            'ERROR': logger.error,
            'WARNING': logger.warning,
            'CRITICAL': logger.critical,
            'EXCEPTION': logger.exception,
        }.get(level, logger.info)

    def map_log_level(self, log_level='INFO'):
        log_level = log_level.upper()
        return {
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'CRITICAL': logging.CRITICAL,
        }.get(log_level, logging.INFO)

    @abstractmethod
    def add_log_handler(self, loc_logger):
        pass

    def create_log(self):
        global logger
        global loggerName
        logger = logging.getLogger(loggerName)
        self.add_log_handler(logger)
        self.log("Created log " + loggerName, 'info')

    def set_log_level(self, log_level='INFO'):
        logger.setLevel(self.map_log_level(log_level))

    @abstractmethod
    def get_console_address(self):
        pass

    @abstractmethod
    def root_path(self):
        pass

    def get_root_path(self,relative_path):
        return os.path.join(self.root_path(), relative_path)

    def store_path(self):
        return os.path.join(self.root_path(), 'store')

    def get_store_path(self, relative_path):
        return os.path.join(self.store_path(), relative_path)

    @abstractmethod
    def get_cert_file(self, address, do_not_use_local_ca_bundle=False):
        pass

    def get_pem_issuer_name(self, pem):
        try:
            from cryptography import x509
            oid = getattr(x509, 'OID_COMMON_NAME')
            issuer = pem.issuer
            info = issuer.get_attributes_for_oid(oid)
            if len(info) == 0:
                return ''
            else:
                return info[0].value
        except ImportError:
            return ''

    def get_pem_subject_name(self, pem):
        try:
            from cryptography import x509
            oid = getattr(x509, 'OID_COMMON_NAME')
            subject = pem.subject
            info = subject.get_attributes_for_oid(oid)
            if len(info) == 0:
                return ''
            else:
                return info[0].value
        except ImportError:
            return ''

    def to_json_dict(self, python_obj, classkey=None):
        """
        Helper function to convert a Python object into a dict
        usable with the JSON REST.
        Recursively converts fields which are also Python objects.
        @param python_obj: Python object to be converted into a dict
        @return dict object containing key:value pairs for the python
        objects fields. Useable with JSON REST.
        """
        if isinstance(python_obj, dict):
            data = {}
            for (k, v) in python_obj.items():
                data[k] = self.to_json_dict(v, classkey)
            return data
        elif hasattr(python_obj, "_ast"):
            return self.to_json_dict(python_obj._ast())
        elif hasattr(python_obj, "__iter__"):
            return [self.to_json_dict(v, classkey) for v in python_obj]
        elif hasattr(python_obj, "__dict__"):
            data = dict([(key, self.to_json_dict(value, classkey))
                         for key, value in python_obj.__dict__.iteritems()
                         if not callable(value) and not key.startswith('_')])
            if classkey is not None and hasattr(python_obj, "__class__"):
                data[classkey] = python_obj.__class__.__name__
            return data
        else:
            return python_obj

    @abstractmethod
    def get_app_base_url(self):
        pass

    def q_url_for(self, endpoint, **values):
        """
        Create a method to wrap the standard Flask url_for())method,
        to include the proxied url through Qradar as a prefix to the
        short-name Flask route name
        """
        url = self.get_app_base_url() + url_for(endpoint, **values)
        self.log("q_url_for==>" + url, 'debug')
        return url

    def map_notification_code(self, log_level='INFO'):
        log_level = log_level.upper()
        return {
            'INFO': "0000006000",
            'DEBUG': "0000006000",
            'ERROR': "0000003000",
            'WARNING': "0000004000",
            'CRITICAL': "0000003000",
        }.get(log_level, "0000006000")

    def log(self, message,  level='info'):
        log_fn = self.choose_log_level(level)
        log_fn("127.0.0.1 " +
               "[APP_ID/" +  self.get_app_id() + "]" +
               "[NOT:" +  self.map_notification_code(level) + "] " +
               message)

    def register_jsonld_type(self, context):
        if context is not None:
            jsonld_type = self.extract_type(context)
            self.log("Registering JSONLD type " + str(jsonld_type) , "info")
            json_qpylib.register_jsonld_type(jsonld_type, context)

    def get_jsonld_type(self, jsonld_type):
        self.log("getting JSONLD type " + str(jsonld_type) , "debug")
        return json_qpylib.get_jsonld_type(jsonld_type)

    def choose_offense_rendering(self, render_type):
        render_type_upper = render_type.upper()
        self.log( 'choose_offense_rendering '+str(render_type_upper), 'debug' )
        return {
            'HTML': offense_qpylib.get_offense_json_html,
            'JSONLD': offense_qpylib.get_offense_json_ld,
        }.get(render_type_upper, offense_qpylib.get_offense_json_html)

    def get_offense_rendering(self, offense_id, render_type):
        rendering_fn = self.choose_offense_rendering(render_type)
        return rendering_fn(offense_id)

    def choose_asset_rendering(self, render_type):
        render_type_upper = render_type.upper()
        self.log( 'choose_asset '+str(render_type_upper), 'debug' )
        return {
            'HTML': asset_qpylib.get_asset_json_html,
            'JSONLD': asset_qpylib.get_asset_json_ld,
        }.get(render_type_upper, asset_qpylib.get_asset_json_html)

    def get_asset_rendering(self, asset_id, render_type):
        rendering_fn = self.choose_asset_rendering(render_type)
        return rendering_fn(asset_id)

    def extract_jsonld_context(self, argument, mime_id, context_id):
        if mime_id in argument.keys() and context_id in argument.keys():
            if argument[mime_id] == 'application/json+ld':
                return argument[context_id]

    def extract_type(self, argument):
        type_id=None
        if '@context' in argument.keys():
            context=argument['@context']
            if '@type' in context.keys():
                type_id=context['@type']
            if type_id == '@id' and '@id' in context.keys():
                type_id=context['@id']
        return type_id

    def register_jsonld_endpoints(self):
        manifest = self.get_manifest_json()
        services=None
        endpoints=None
        if 'services' in manifest.keys():
            services=manifest['services']

        if services is not None:
            for service in services:
                if 'endpoints' in service.keys():
                    endpoints=service['endpoints']

        if endpoints is not None:
            for endpoint in endpoints:
                jsonld_context = None
                if 'request_mime_type' in endpoint.keys():
                    argument=endpoint
                    jsonld_context = self.extract_jsonld_context(argument, 'request_mime_type', 'request_body_type')
                    self.register_jsonld_type(jsonld_context)
                if 'response' in endpoint.keys():
                    argument = endpoint['response']
                    jsonld_context = self.extract_jsonld_context(argument, 'mime_type', 'body_type')
                    self.register_jsonld_type(jsonld_context)

    def render_json_ld_type(self, jld_type, data, jld_id = None):
        return json_qpylib.render_json_ld_type(jld_type, data, jld_id)

