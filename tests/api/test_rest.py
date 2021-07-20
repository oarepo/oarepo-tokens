# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""
import json
import time
import requests
import re
from flask import url_for
from invenio_access import ActionRoles
from invenio_accounts.models import Role, User
from invenio_accounts.proxies import current_datastore

from oarepo_tokens.models import OARepoAccessToken


def test_token_list(client, oartoken):
    # resp = client.get('https://localhost/access-tokens/')
    resp = client.get('/access-tokens/')
    assert resp.status_code == 200
    assert len(resp.json) == 1
    assert resp.json['tokens'][0]['id'] == oartoken.id
    assert resp.json['tokens'][0]['repr'] == oartoken.__repr__()


def test_token_detail(client, oartoken):
    # resp = client.get(f"https://localhost/access-tokens/{oartoken.id}")
    resp = client.get(f"/access-tokens/{oartoken.id}")
    assert resp.status_code == 200
    # assert resp.json['token'] == oartoken.token
    assert resp.json['repr'] == oartoken.__repr__()
    assert resp.json['status'] == 'OK'
    assert OARepoAccessToken.get_by_token(oartoken.token).is_valid()


def test_create_token(app_config, client, draft_record):
    drec_pid = draft_record[app_config['PIDSTORE_RECID_FIELD']]
    resp = client.get(f"/draft/records/{drec_pid}")
    assert resp.status_code == 200
    assert resp.json['id'] == str(drec_pid)
    resp = client.post(f"/draft/records/{drec_pid}/create_token")
    assert resp.status_code == 200
    assert resp.json['rec_uuid'] == str(draft_record.id)
    newtoken_string = resp.json['token']
    newtoken = OARepoAccessToken.get_by_token(newtoken_string)
    assert newtoken.is_valid()

def test_mocked_s3_client(app_config):
    assert app_config['S3_CLIENT'] == 'tests.api.conftest.MockedS3Client'

def test_upload_abort(app, app_config, client, oartoken, draft_record, sample_upload_data):
    drec_pid = draft_record[app_config['PIDSTORE_RECID_FIELD']]
    assert drec_pid == '1'
    # ------ test record ------ :
    resp = client.get(f"/draft/records/{drec_pid}")
    assert resp.status_code == 200
    # ------ init without token ------ :
    init_url = f"/draft/records/{drec_pid}/files/?multipart=true"
    headers = { 'Content-Type': 'application/json' }
    resp = client.post(init_url, data=sample_upload_data['fileinfo_json'], headers=headers)
    assert resp.status_code == 401
    # ------ init with token ------ :
    headers = { 'Content-Type': 'application/json', 'Authorization': f"Bearer {oartoken.token}" }
    resp = client.post(init_url, data=sample_upload_data['fileinfo_json'], headers=headers)
    # assert json.dumps(resp.json,indent=2) == ''
    assert resp.status_code == 201
    assert 'uploadId' in resp.json
    assert 'key' in resp.json
    uploadId = resp.json['uploadId']
    assert uploadId
    # ------ check parts ------ :
    key = sample_upload_data['fileinfo']['key']
    parts_url = f"/draft/records/{drec_pid}/files/{key}/{uploadId}/parts"
    resp = client.get(parts_url)
    assert resp.status_code == 200
    assert len(resp.json) == 0
    # ------ try abort ------ :
    abort_url = f"/draft/records/{drec_pid}/files/{key}/{uploadId}/abort"
    resp = client.delete(abort_url)
    assert resp.status_code == 200
    # ------ abort again ------ :
    resp = client.delete(abort_url)
    assert resp.status_code == 404


def test_upload_complete(app, app_config, client, oartoken, draft_record, sample_upload_data):
    drec_pid = draft_record[app_config['PIDSTORE_RECID_FIELD']]
    # ------ init with token ------ :
    init_url = f"/draft/records/{drec_pid}/files/?multipart=true"
    headers = { 'Content-Type': 'application/json', 'Authorization': f"Bearer {oartoken.token}" }
    resp = client.post(init_url, data=sample_upload_data['fileinfo_json'], headers=headers)
    assert resp.status_code == 201
    uploadId = resp.json['uploadId']
    assert uploadId
    # time.sleep(10)
    # assert json.dumps(resp.json,indent=2) == ''
    # ------ check parts ------ :
    key = sample_upload_data['fileinfo']['key']
    parts_url = f"/draft/records/{drec_pid}/files/{key}/{uploadId}/parts"
    resp = client.get(parts_url)
    assert resp.status_code == 200
    assert len(resp.json) == 0
    # ------ get presigned url for part 1 ------ :
    partnum = 1
    presign_url = f"/draft/records/{drec_pid}/files/{key}/{uploadId}/{partnum}/presigned"
    resp = client.get(presign_url)
    # assert json.dumps(resp.json,indent=2) == ''
    assert resp.status_code == 200
    assert 'url' in resp.json
    part_url = resp.json['url']
    assert part_url
    # assert part_url == ''
    # ------ upload part 1 ------ :
    # headers = { 'Content-Length': sample_upload_data['fileinfo']['size'] }
    # resp = requests.put(part_url, data=sample_upload_data['data'], headers=headers)
    # assert resp.status_code == 200
    # ------ check parts ------ :
    # resp = client.get(parts_url)
    # assert resp.status_code == 200
    # assert len(resp.json) == 1
    # ------ complete upload ------ :
    complete_url = f"/draft/records/{drec_pid}/files/{key}/{uploadId}/complete"
    headers = { 'Content-Type': 'application/json' }
    partinfo = {"parts": [{"ETag": "1d64dce239c4437b7736041db089e1b9", "PartNumber": 1}]}
    resp = client.post(complete_url, data=json.dumps(partinfo), headers=headers)
    assert resp.status_code == 200
    assert 'location' in resp.json
    assert re.match(f".*/draft/records/{drec_pid}/files/{key}$", resp.json['location'])
    # ------ get download url ------ :
    headers = { 'Content-Type': 'application/json', 'Authorization': f"Bearer {oartoken.token}" }
    resp = client.get(resp.json['location'], headers=headers)
    assert resp.status_code == 302
    assert re.match("https://.*", resp.headers['Location'])
    # ------ download ------ :
    # assert resp.headers['Location'] == ''
    # resp = requests.get(resp.headers['Location'])
    # assert resp.status_code == 200
    # assert resp.content == sample_upload_data['data']
    # assert json.dumps(resp.json,indent=2) == ''
