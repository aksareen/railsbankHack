# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-11 17:53
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='BankAccounts',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ledger_id', models.CharField(max_length=256, verbose_name='Ledger Id')),
                ('preference', models.IntegerField(default=1, verbose_name='Preference')),
                ('iban', models.CharField(max_length=100, verbose_name='IBAN')),
                ('swift_code', models.CharField(max_length=50, verbose_name='Swift Code')),
                ('account_name', models.CharField(max_length=256, verbose_name='Account Name')),
            ],
        ),
        migrations.CreateModel(
            name='Users',
            fields=[
                ('username', models.CharField(max_length=30, primary_key=True, serialize=False, verbose_name='Username')),
                ('password', models.CharField(max_length=270, null=True, verbose_name='Password')),
                ('enduser_id', models.CharField(max_length=200, unique=True, verbose_name='End User Id')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email')),
            ],
        ),
        migrations.AddField(
            model_name='bankaccounts',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='apis.Users', verbose_name='the related User'),
        ),
    ]
