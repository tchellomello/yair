# -*- coding: utf-8 -*-
# vim:sw=4:ts=4:et
import os
import yaml
import requests
import logging
"""Yair core object."""

DEFAULT_CONFIG = '/opt/yair/config/config.yaml'

CLAIR_JSON_TEMPLATE = {
    "Layer": { 
        "Name": "", 
            "Path": "", 
            "Headers": {
            "Authorization": "" 
        }, 
        "ParentName": "",
        "Format": "" 
    }
}

logger = logging.getLogger(__name__)


class Yair(object):
    """Yair object."""

    def __init__(self, image, config_file=None, registry=None, 
                 no_namespace=False, auto_load=True):
        self._yaml = self._parse_config(config_file)

        # some args that can be overridden via cli
        self._registry = registry
        self._no_namespace = no_namespace

        self.image_name, self.image_tag = self._parse_image(image)

        # handle requests session
        self.session = requests.Session()
        self.session.verify = self.docker_registry_ssl_verify

        # initiate attributes
        self.data = None
        self._registry_token = None

        if auto_load:
            self.run()

    def _parse_config(self, config_file):
        try:
            with open(config_file, 'r') as cfg:
                return yaml.load(cfg)
        except yaml.parser.ParserError:
            raise(f'error while parsing {config_file}')
        except FileNotFoundError:
            raise(f"config file {config_file} not found - exiting")

    def _parse_image(self, image):
        try:
            image, image_tag = image.rsplit(':', 1)
        except ValueError:
            image_tag = "latest"

        image_s = image.split('/')
        if image_s and len(image_s) == 1:
            if self._no_namespace:
                image_name = image
            else:
                image_name = f'library/{image}'
        else:
            image_name = image
        return image_name, image_tag

    def _get_config_value(self, key, value, default=None):
        return self._yaml.get(key).get(value, default)

    def _connect(self, url, headers=None, data=None, method='GET'):
        #TODO: authentication + error treatment

        if method == 'DELETE':
            req = self.session.delete(url, headers=headers, data=data)
        else:
            req = self.session.get(url, headers=headers, data=data)

        #req.raise_for_status()
        return req
        
    @property
    def image_score_fail_on(self):
        return self._get_config_value('fail_on', 'score')

    @property
    def big_vuln_fail_on(self):
        return self._get_config_value('fail_on', 'big_vulnerability')

    @property
    def docker_registry_url(self):
        url = (
            f'{self.docker_registry_protocol}://{self.docker_registry}:'
            f'{self.docker_registry_port}/v2/{self.image_name}/manifests/{self.image_tag}'
        )
        return url

    @property
    def docker_registry(self):
        if self._registry:
            return self._registry
        return self._get_config_value('registry', 'host')

    @property
    def docker_registry_ssl(self, default=True):
        return bool(self._get_config_value('registry', 'ssl', True))

    @property
    def docker_registry_ssl_verify(self):
        return bool(self._get_config_value('registry', 'ssl_verify', True))

    @property
    def docker_registry_port(self):
        port = self._get_config_value('registry', 'port')
        if port is None:
            if self.docker_registry_ssl:
                port = 443
            else:
                port = 80
        return int(port)

    @property
    def docker_registry_protocol(self):
        if self.docker_registry_ssl:
            return 'https'
        return 'http'

    @property
    def output(self):
        return self._yaml['output']['format']

    @property
    def clair_server(self):
        return self._get_config_value('clair', 'host')

    @property
    def clair_server_ssl(self, default=True):
        return bool(self._get_config_value('clair', 'ssl', True))

    @property
    def clair_server_ssl_verify(self):
        return bool(self._get_config_value('clair', 'ssl_verify', True))

    @property
    def clair_server_port(self, default=6060):
        return self._get_config_value('clair', 'port')

    @property
    def clair_server_protocol(self):
        if self.clair_server_ssl:
            return 'https'
        return 'http'

    @property
    def clair_server_url(self):
        url = (
            f'{self.clair_server_protocol}://{self.clair_server}:'
            f'{self.clair_server_port}/v1/layers/{self.image_layers[-1]}'
        )
        return url

    def __clair_cleanup_latest_layer(self):
        #try:
        req = self._connect(self.clair_server_url, method='DELETE')
        print(req.status_code)
            #if req.status_code != 404:
        #except requests.exceptions.HTTPError as err:
        #    continue
        #except requests.exceptions.ConnectionError as err:
        #    raise(f'Connection to {self.clair_server_url} failed.')

    def run(self):
        self.get_image_manifest()
        self.get_image_layers()
        self.analyse_image()

    def get_image_manifest(self):
        req_headers = {}
        req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'

        try:
            req = self._connect(self.docker_registry_url, headers=req_headers)
            if req.status_code == 404:
                raise ValueError("image not found")
            elif req.status_code == 200:
                self.data = req.json()
        except:
            self.data = None

    def get_image_layers(self):
        if self.data is None:
            return
        
        if self.data.get('schemaVersion') == 1:
            result = list(map(lambda x: x['blobSum'], self.data['fsLayers']))
            result.reverse() # schema v1 need the reversed order
        elif self.data.get('schemaVersion') == 2:
            result = list(map(lambda x: x['digest'], self.data['layers']))
        else:
            raise NotImplementedError("unknown schema version")
        return result

    @property
    def image_layers(self):
        return self.get_image_layers()
        
    def analyse_image(self):
        self.__clair_cleanup_latest_layer()

        for layer in range(0, len(self.image_layers)):
            json_data = CLAIR_JSON_TEMPLATE.copy()
            json_data['Layer']['Name'] = self.image_layers[layer]
            json_data['Layer']['Path'] = self.docker_registry_url.replace('/manifests/', '/blobs').replace(self.image_tag, self.image_layers[layer])
            json_data['Layer']['Format'] = "Docker"
            json_data['Layer']['Headers']['Authorization'] = self._registry_token

            if layer > 0:
                json_data['Layer']['ParentName'] = self.image_layers[layer-1]

            headers = { 'Content-Type': 'application/json' }

            url = (
                f'{self.clair_server_protocol}://{self.clair_server}:'
                f'{self.clair_server_port}/v1/layers'
            )

            print(json_data)
