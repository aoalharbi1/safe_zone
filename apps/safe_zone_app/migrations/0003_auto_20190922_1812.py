# -*- coding: utf-8 -*-
# Generated by Django 1.10 on 2019-09-22 18:12
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('safe_zone_app', '0002_auto_20190922_1720'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(max_length=225),
        ),
    ]
