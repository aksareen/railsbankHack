# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-11-11 18:27
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('apis', '0001_initial'),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name='bankaccounts',
            unique_together=set([('user', 'preference')]),
        ),
    ]
