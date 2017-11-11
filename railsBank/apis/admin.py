# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin

# Register your models here.
from .models import Users, BankAccounts


from django.contrib.admin.options import ModelAdmin


class CustomUserAdmin(ModelAdmin):
    list_display = ('username', 'email', 'enduser_id')
    list_filter = ('username', 'email', 'enduser_id')
    search_fields = ('username', 'email', 'enduser_id')
    ordering = ('username',)


class CustomBankAccountsAdmin(ModelAdmin):
    list_display = ('user', 'ledger_id', 'preference', 'account_name')
    list_filter = ('user', 'ledger_id')
    search_fields = ('user', 'ledger_id', 'preference', 'account_name')
    ordering = ('user',)

admin.site.register(Users, CustomUserAdmin)
admin.site.register(BankAccounts, CustomBankAccountsAdmin)