# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
from railsBank.settings import RAILSBANK_API_KEYS
from apis.models import Users, BankAccounts
import pprint

# Create your views here.
from django.http import HttpResponse
from django.middleware.csrf import get_token

from django.views.decorators.csrf import csrf_exempt
import requests

import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()


import certifi
import urllib3
http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())


def get_csrf_token(request):
    if request.method == "GET":
        response = HttpResponse(content_type="text/plain", status=200)
        response.__setitem__("csrf_token", get_token(request))
        return response


@csrf_exempt
def add_user(request):
    if request.method == "POST":
        body = json.loads(request.body)
        email = body["person"]["email"]
        username = body["person"]["username"]
        del body["person"]["username"]

        print("body: {}".format(body))
        url = 'https://play.railsbank.com/v1/customer/endusers'
        headers = {'Content-Type': 'application/json',
                   'Accept': 'application/json',
                   'Authorization': RAILSBANK_API_KEYS}
        try:
            resp = requests.post(url=url, json=body, headers=headers)
        except Exception as e:
            print("{}".format(e))
            content = {"error": "{}".format(e)}
            return HttpResponse(content, content_type="application/json", status=400)

        if resp.status_code == requests.codes.ok:
            print("response: type : {} , body: {}".format(type(resp), resp.json()))
            enduser_id = resp.json().get("enduser_id")
            print("EndUser: {}".format(enduser_id))
            new_user = Users(username=username, password="1234", enduser_id=enduser_id, email=email)
            new_user.save()
            return HttpResponse(resp, status=200, content_type="application/json")
        else:
            return HttpResponse(resp, content_type="application/json", status=400)
