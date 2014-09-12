#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import flask
app = flask.Flask(__name__)
app.secret_key='test'

from hotcidrdash import views
