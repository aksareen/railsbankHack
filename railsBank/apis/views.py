# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import re
from railsBank.settings import RAILSBANK_API_KEYS
from apis.models import Users, BankAccounts

# Create your views here.
from django.http import HttpResponse, response
from django.middleware.csrf import get_token

from django.views.decorators.csrf import csrf_exempt
import requests

import urllib3.contrib.pyopenssl
urllib3.contrib.pyopenssl.inject_into_urllib3()

import uuid
import logging
logger = logging.getLogger(__name__)

import hashlib
import certifi
import urllib3
http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())


def get_csrf_token(request):
    if request.method == "GET":
        response = HttpResponse(content_type="text/plain", status=200)
        response.__setitem__("csrf_token", get_token(request))
        return response


def _default400(exception):
    logger.info("{}".format(exception))
    return HttpResponse({"error": "{}".format(exception)},
                        content_type="application/json",
                        status=400)


def _hash_password(password):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt


def _check_password(hashed_password, unhashed_user_password):
    password, salt = hashed_password.split(':')
    return password == hashlib.sha256(salt.encode() + unhashed_user_password.encode()).hexdigest()


EMAIL_REGEX = "[^@]+@[^@]+\.[^@]+"


# can have man in middle attack but need to skip this for live demo.
# as short on time.
@csrf_exempt
def sign_in(request):
    if request.method != "POST":
        return HttpResponse("only POST operations permitted",
                            content_type="text/plain",
                            status=400)
    try:
        body = json.loads(request.body)
    except Exception as e:
        return _default400(e)

    uname = body["username"]
    inp_password = body["password"]

    is_email = False
    if re.match(EMAIL_REGEX, uname):
        is_email = True

    if is_email:
        try:
            user = Users.objects.get(email=uname)
        except Users.DoesNotExist:
            return HttpResponse("user with email: {} did not exist".format(uname),
                                status=404,
                                content_type="text/plain")
        except Users.MultipleObjectsReturned:
            logger.exception("multiple user exists for email: {} ".format(uname))
            return HttpResponse("Multiple Users with email: {} exist".format(uname),
                                status=500,
                                content_type="text/plain")
    else:
        try:
            user = Users.objects.get(username=uname)
        except Users.DoesNotExist:
            return HttpResponse("user with username: {} did not exist".format(uname),
                                status=404,
                                content_type="text/plain")
        except Users.MultipleObjectsReturned:
            logger.exception("multiple user exists for username: {} ".format(uname))
            return HttpResponse("Multiple Users with username: {} exist".format(uname),
                                status=500,
                                content_type="text/plain")

    if not _check_password(user.password, inp_password):
        return HttpResponse("Username/password pair did not match",
                            status=400,
                            content_type="text/plain")

    resp_body = {"enduser_id": user.enduser_id}
    logger.info(resp_body)
    return HttpResponse(resp_body, content_type="application/json", status=200)


# TODO: should be csrf_protect but cannot do right now due to time limits.
@csrf_exempt
def add_user(request):
    if request.method != "POST":
        return HttpResponse("only POST operations permitted",
                            content_type="text/plain",
                            status=400)
    try:
        body = json.loads(request.body)
    except Exception as e:
        return _default400(e)

    email = body["person"]["email"]
    username = body["person"]["username"]

    # this is stupid. period.
    password = body["person"]["password"]

    del body["person"]["password"]
    del body["person"]["username"]

    logger.debug("body: {}".format(body))
    url = 'https://play.railsbank.com/v1/customer/endusers'
    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': RAILSBANK_API_KEYS}
    try:
        resp = requests.post(url=url, json=body, headers=headers)
    except Exception as e:
        return _default400(e)

    if resp.status_code == requests.codes.ok:
        logger.debug("response: type : {} , body: {}".format(type(resp), resp.json()))
        enduser_id = resp.json().get("enduser_id")
        new_user = Users(username=username, password=_hash_password(password),
                         enduser_id=enduser_id, email=email)

        try:
            new_user.save()
        except Exception as e:
            return _default400(e)
        return HttpResponse(resp, status=200, content_type="application/json")

    else:
        return HttpResponse(resp, content_type="application/json", status=400)


def _get_user_from_user_id(enduser_id):
    try:
        user = Users.objects.get(enduser_id=enduser_id)
    except Users.DoesNotExist:
        return True, HttpResponse("user with enduser_id: {} did not exist".format(enduser_id),
                                  status=404,
                                  content_type="text/plain")
    except Users.MultipleObjectsReturned:
        logger.exception("Multiple user exists for enduser_id: {} ".format(enduser_id))
        return True, HttpResponse("Multiple Users with enduser_id: {} exist".format(enduser_id),
                                  status=500,
                                  content_type="text/plain")
    return False, user


# adds only the existing ledgers and iBans , does not create new ones.
@csrf_exempt
def add_bank_account(request):
    if request.method != "POST":
        return HttpResponse("only POST operations permitted",
                            content_type="text/plain",
                            status=400)
    try:
        body = json.loads(request.body)
    except Exception as e:
        return _default400(e)

    enduser_id = body["enduser_id"]
    preference = body["preference"]
    val, resp = _get_user_from_user_id(enduser_id)
    if val:
        return resp
    user = resp

    if len(user.bankaccounts_set.all()) == 0:
        global preference
        preference = 1
    else:
        # change the preference of all bank accounts
        for i in user.bankaccounts_set.all():
            pass

@csrf_exempt
def get_user_details(request):
    if request.method != "POST":
        return HttpResponse("only POST operations permitted",
                            content_type="text/plain",
                            status=400)
    try:
        body = json.loads(request.body)
    except Exception as e:
        return _default400(e)

    enduser_id = body["enduser_id"]
    val, resp = _get_user_from_user_id(enduser_id)
    if val:
        return resp
    user = resp
    response = {
        "username": user.username,
        "enduser_id": user.enduser_id,
        "email": user.email,
        "totalSavings": user.totalSavings
    }
    response = json.dumps(response)
    return HttpResponse(response, content_type="application/json", status=200)


@csrf_exempt
def get_bank_accounts(request):
    if request.method != "POST":
        return HttpResponse("only POST operations permitted",
                            content_type="text/plain",
                            status=400)
    try:
        body = json.loads(request.body)
    except Exception as e:
        return _default400(e)

    enduser_id = body["enduser_id"]
    val, resp = _get_user_from_user_id(enduser_id)
    if val:
        return resp
    user = resp
    resp_list = []
    for bankaccs in user.bankaccounts_set.all():
        acc = {}
        acc["user"] = enduser_id
        acc["ledger_id"] = bankaccs.ledger_id
        acc["preference"] = bankaccs.preference
        acc["iban"] = bankaccs.iban
        acc["swift_code"] = bankaccs.swift_code
        acc["account_name"] = bankaccs.account_name
        resp_list.append(acc)
    rsp = json.dumps({"accounts": resp_list})
    logger.info(rsp)
    return HttpResponse(rsp, content_type="application/json", status=200)
