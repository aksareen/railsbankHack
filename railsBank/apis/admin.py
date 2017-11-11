# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from .models import Users, BankAccounts

admin.site.register(Users)
admin.site.register(BankAccounts)