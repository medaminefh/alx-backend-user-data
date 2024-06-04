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
        for ex_path in excluded_paths:
            if ex_path[-1] != '/':
                ex_path += '/'
            if path == ex_path:
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
