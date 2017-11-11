# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.utils.encoding import python_2_unicode_compatible

from django.db import models


@python_2_unicode_compatible
class Users(models.Model):
    username = models.CharField('Username', max_length=30, primary_key=True)
    password = models.CharField('Password', max_length=256, null=True)
    enduser_id = models.CharField('End User Id', unique=True, max_length=200)
    email = models.EmailField('Email')

    def __str__(self):
        return self.enduser_id.__str__()


@python_2_unicode_compatible
class BankAccounts(models.Model):
    user = models.ForeignKey(Users, on_delete=models.CASCADE, verbose_name="the related User")
    ledger_id = models.CharField('Ledger Id', max_length=256)
    preference = models.IntegerField('Preference', default=100) # order of preference
    account_name = models.CharField('Account Name', max_length=256)

    def __str__(self):
        return self.ledger_id.__str__()
