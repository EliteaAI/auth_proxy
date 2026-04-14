#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Route """

import datetime

import flask  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401,W0611
from pylon.core.tools import web  # pylint: disable=E0611,E0401

from tools import auth_core  # pylint: disable=E0401


class Route:  # pylint: disable=E1101,R0903
    """
        Route Resource

        self is pointing to current Module instance

        By default routes are prefixed with module name
        Example:
        - pylon is at "https://example.com/"
        - module name is "demo"
        - route is "/"
        Route URL: https://example.com/demo/

        web.route decorator takes the same arguments as Flask route
        Note: web.route decorator must be the last decorator (at top)
    """

    @web.route("/login")
    def login(self):
        """ Login """
        target_token = flask.request.args.get("target_to", "")
        user_email_header = self.descriptor.config.get("user_email_header")
        #
        if user_email_header not in flask.request.headers:
            log.error("User email header is not present: %s", user_email_header)
            return auth_core.access_denied_reply()
        #
        header_data = flask.request.headers.get(user_email_header)
        email = header_data.strip()
        #
        if "@" not in email:
            log.error("Invalid email: '%s'", email)
            return auth_core.access_denied_reply()
        #
        name = email.rsplit("@", 1)[0].strip().replace("_", " ").replace(".", " ")
        #
        auth_attributes = {
            "email": email,
            "name": name,
        }
        #
        exp_override = self.descriptor.config.get("expiration_override", None)
        #
        if exp_override is not None:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=int(exp_override))
        else:
            auth_exp = datetime.datetime.now() + datetime.timedelta(seconds=86400)  # 24h
        #
        auth_sessionindex = auth_core.get_auth_reference()
        #
        if isinstance(auth_sessionindex, bytes):
            auth_sessionindex = auth_sessionindex.decode()
        #
        try:
            auth_user_id = auth_core.get_user_from_provider(email)["id"]
        except:  # pylint: disable=W0702
            auth_user_id = None
        #
        auth_ctx = auth_core.get_auth_context()
        auth_ctx["done"] = True
        auth_ctx["error"] = ""
        auth_ctx["expiration"] = auth_exp
        auth_ctx["provider"] = "proxy"
        auth_ctx["provider_attr"]["nameid"] = email
        auth_ctx["provider_attr"]["attributes"] = auth_attributes
        auth_ctx["provider_attr"]["sessionindex"] = auth_sessionindex
        auth_ctx["user_id"] = auth_user_id
        auth_core.set_auth_context(auth_ctx)
        #
        return auth_core.access_success_redirect(target_token)

    @web.route("/logout")
    def logout(self):
        """ Logout """
        target_token = flask.request.args.get("target_to", "")
        return auth_core.logout_success_redirect(target_token)
