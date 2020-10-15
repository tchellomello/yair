#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim:sw=4:ts=4:et
"""Yair command line."""
import os
import argparse
import argcomplete
import yaml

from core import Yair, DEFAULT_CONFIG

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Command line interface for Yair.',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('--config',
                        dest='config_file',
                        action='store',
                        default='/opt/yair/config/config.yaml',
                        help=f'config file location. Default: {DEFAULT_CONFIG}')

    parser.add_argument('--no-namespace',
                        dest='no_namespace',
                        action='store_true',
                        default=False,
                        help='If your image names doesnt contain the \"namespace\" and its not in the default \"library\" namespace.')

    parser.add_argument('--registry',
                        action='store',
                        help='Overwrites the \"registry::host\" configfile option.')

    parser.add_argument('image',
                        action='store',
                        help='The image you want to scan. if you provide no tag we will assume \"latest\". if you provide no namespace we will assume \"library\".')

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not os.path.isfile(args.config_file):
        print("File does not exit")


    yair = Yair()
    yair.run()


