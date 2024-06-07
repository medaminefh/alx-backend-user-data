#!/usr/bin/env python3
"""
Module of auth
"""

from flask import request
from typing import TypeVar


class Auth():
    """ Auth class
    """

    def require_auth(self, path: str, excluded_paths: list) -> bool:
        """ Require auth
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        if path[-1] != '/':
            path += '/'
        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                excluded_path = excluded_path[:-1]
                if path.startswith(excluded_path):
                    return False
            elif path == excluded_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Authorization header
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Current user
        """
        return None
