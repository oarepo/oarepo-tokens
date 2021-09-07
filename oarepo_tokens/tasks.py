# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OARepo-Tokens tasks."""

from datetime import datetime
from celery import shared_task
from oarepo_tokens.models import OARepoAccessToken

@shared_task
def cleanup_expired_access_tokens():
    dt_now = datetime.utcnow()
    removed = OARepoAccessToken.delete_expired(dt_now)
    resp = [item.id for item in removed]
    return resp
