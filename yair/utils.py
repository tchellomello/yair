# -*- coding: utf-8 -*-
# vim:sw=4:ts=4:et


def get_config_value(self, key, value):
    return [_.yaml.get(key).get(value, None) for _ in self]
    for idx in self._yaml.items():
        if idx == key:
            return self._yaml.get(key).get(value, None)