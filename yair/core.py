# -*- coding: utf-8 -*-
# vim:sw=4:ts=4:et
import os
import yaml
import requests
"""Yair core object."""

DEFAULT_CONFIG = '/opt/yair/config/config.yaml'


class Yair(object):
    """Yair object."""

    def __init__(self, image, config_file=None, registry=None, no_namespace=False):
        self._yaml = self._parse_config(config_file)

        # some args that can be overridden via cli
        self._registry = registry
        self._no_namespace = no_namespace

        self.image_name, self.image_tag = self._parse_image(image)

        # handle requests session
        self.session = requests.Session()
        self.session.verify = self.docker_registry_ssl_verify


    def _parse_config(self, config_file):
        try:
            with open(config_file, 'r') as cfg:
                return yaml.load(cfg)
        except yaml.parser.ParserError:
            raise(f'error while parsing config.yaml')
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

    @property
    def image_score_fail_on(self):
        return self._yaml['fail_on']['score']

    @property
    def big_vuln_fail_on(self):
        return bool(self._yaml['fail_on']['big_vulnerability'])

    @property
    def docker_registry(self):
        if self._registry:
            return self._registry
        return self._yaml['registry']['host']

    @property
    def docker_registry_ssl(self):
        return bool(self._yaml.get('registry').get('ssl', True))

    @property
    def docker_registry_ssl_verify(self):
        return bool(self._yaml.get('registry').get('ssl_verify', True))

    @property
    def docker_registry_port(self):
        port = self._yaml.get('registry').get('port')

        if port is None:
            if self.docker_registry_ssl:
                port = 443
            else:
                port = 80
        return int(port)

    @property
    def _docker_registry_protocol(self):
        if self.docker_registry_ssl:
            proto = 'https'
        else:
            proto = 'http'
        return proto

    @property
    def output(self):
        return self._yaml['output']['format']

    @property
    def clair_server(self):
        return self._yaml['clair']['host']

    def run(self):
        print("running")

    def get_image_manifest(self):
        req_headers = {}
        req_headers['Accept'] = 'application/vnd.docker.distribution.manifest.v2+json'

        req_url = f'{self._docker_registry_protocol}://{self.docker_registry}:{self.docker_registry_port}/v2/{self.image_name}/manifests/{self.image_tag}'

        req = self.session.get(req_url, headers=req_headers)
        req.raise_for_status()

        print(req)
        print(req_url)
        return req

