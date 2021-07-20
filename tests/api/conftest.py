# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""Pytest configuration.

See https://pytest-invenio.readthedocs.io/ for documentation on which test
fixtures are available.
"""
import logging
import os
import pytest
import uuid
# import tempfile
import boto3
import json
from flask import Blueprint
from datetime import datetime
from pathlib import Path
from invenio_accounts.models import User
from invenio_accounts.testutils import create_test_user
from invenio_app.factory import create_api
from tests.api.helpers import gen_rest_endpoint, gen_rest_endpoint_draft, _test_login_factory
from invenio_indexer.api import RecordIndexer
from invenio_search import RecordsSearch, current_search_client
from invenio_search.cli import destroy, init
from invenio_records_rest.utils import allow_all, deny_all, check_elasticsearch
from invenio_pidstore.models import PersistentIdentifier, PIDStatus
from invenio_files_rest.models import Location

from oarepo_tokens.views import blueprint
from oarepo_tokens.models import OARepoAccessToken
from moto import mock_s3
from oarepo_s3.s3 import S3Client
from s3_client_lib.utils import get_file_chunk_size
from oarepo_s3 import S3FileStorage

#from sample.models import SampleRecord
#from invenio_records import Record
#from  oarepo_references.mixins import ReferenceEnabledRecordMixin
from .helpers import _test_login_factory, record_pid_minter, TestRecord


# logging.basicConfig()
# logging.getLogger('elasticsearch').setLevel(logging.DEBUG)
# logging.getLogger().setLevel(logging.DEBUG)


class MockedS3Client(S3Client):
    """Fake S3 client."""
    parts = []

    def init_multipart_upload(self, bucket, object_name, object_size):
        """Fake init multipart upload implementation."""
        max_parts, chunk_size = get_file_chunk_size(object_size)
        parts = [f'http://localhost/test/{i}' for i in range(1, max_parts + 1)]
        return {"parts_url": parts,
                "chunk_size": chunk_size,
                "checksum_update": "",
                # "upload_id": str(uuid.uuid4()),
                "upload_id": 'qwerty456',
                "origin": "",
                "num_chunks": max_parts,
                "finish_url": ""
                }

    def create_multipart_upload(self, bucket, key, content_type, metadata=None):
        return {
            'key': key,
            'bucket': bucket,
            # "upload_id": str(uuid.uuid4()),
            'upload_id': 'qwerty567'
        }

    def get_uploaded_parts(self, bucket, key, upload_id):
        """Fake list parts that have been fully uploaded so far."""
        return self.parts

    def _add_part(self):
        self.parts += 1
        return self.parts

    def complete_multipart_upload(self, bucket, key, upload_id, parts):
        """Faked complete of a multipart upload to AWS S3."""
        return {'status': 'completed', 'ETag': 'etag:test'}

    def abort_multipart_upload(self, bucket, key, upload_id):
        """Faked cancel of an in-progress multipart upload to AWS S3."""
        return {'status': 'aborted'}


@pytest.fixture(scope='module')
def create_app():
    return create_api


@pytest.fixture(scope='module')
def app_config(app_config):
    app_config = dict(
        TESTING=True,
        APPLICATION_ROOT='/',
        WTF_CSRF_ENABLED=False,
        CACHE_TYPE='simple',
        SERVER_NAME='localhost',
        DEBUG=False,
        PREFERRED_URL_SCHEME='https',
        FLASK_ENV='development',
        PIDSTORE_RECID_FIELD='id',
        EMAIL_BACKEND='flask_email.backends.locmem.Mail',
        SECRET_KEY='TEST',
        SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite://'),
        # SQLALCHEMY_DATABASE_URI=os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:////home/tomash/work/cesnet/work/oarepo/s3/s3-cli/tmp/oardb1.sqlite'),
        SECURITY_DEPRECATED_PASSWORD_SCHEMES=[],
        SQLALCHEMY_TRACK_MODIFICATIONS=True,
        SECURITY_PASSWORD_HASH='plaintext',
        SECURITY_PASSWORD_SCHEMES=['plaintext'],
        APP_ALLOWED_HOSTS=['localhost'],
        USERPROFILES_EXTEND_SECURITY_FORMS=True,
        RATELIMIT_ENABLED=False,
        SEARCH_ELASTIC_HOSTS=os.environ.get('SEARCH_ELASTIC_HOSTS', None),
        RECORDS_DRAFT_ENDPOINTS={
            'record': gen_rest_endpoint('recid',
                                              RecordsSearch,
                                              'tests.api.helpers.TestRecord',
                                              permission_factory=deny_all),
            'draft-record': gen_rest_endpoint_draft('drcid',
                                              RecordsSearch,
                                              'tests.api.helpers.TestRecord',
                                              permission_factory=deny_all)
        },
        S3_TENANT=os.environ.get('S3_TENANT', None),
        S3_SIGNATURE_VERSION=os.environ.get('S3_SIGNATURE_VERSION', None),
        S3_ENDPOINT_URL=os.environ.get('S3_ENDPOINT_URL', None),
        S3_ACCESS_KEY_ID=os.environ.get('S3_ACCESS_KEY_ID', None),
        S3_SECRET_ACCESS_KEY=os.environ.get('S3_SECRET_ACCESS_KEY', None),
    )
    app_config.update(dict(
    #     RATELIMIT_STORAGE_URL=None,
        CELERY_ALWAYS_EAGER=True,
        FILES_REST_STORAGE_FACTORY='oarepo_s3.storage.s3_storage_factory',
        S3_ENDPOINT_URL=None,
        S3_CLIENT='tests.api.conftest.MockedS3Client',
        S3_ACCESS_KEY_ID='test',
        S3_SECRECT_ACCESS_KEY='test',
        FILES_REST_MULTIPART_CHUNKSIZE_MIN=5 * 1024 * 1024,
        OAREPO_TOKENS_TOKEN_NAME='_oarepo_upload_token',
        OAREPO_TOKENS_TOKEN_TTL=600,
    ))
    return app_config


@pytest.fixture(scope='module')
def app(base_app):
    """Flask application fixture."""
    # OARepoEnrollmentsExt(base_app)
    # OARepoTokens(base_app)

    # Register blueprints here
    # base_app.register_blueprint(create_blueprint_from_app(base_app))
    base_app.register_blueprint(blueprint)
    return base_app


@pytest.fixture(scope='module')
def users(base_app):
    yield [create_test_user('user{}@inveniosoftware.org'.format(i)) for i in range(3)]


@pytest.fixture
def authenticated_user(db):
    """Authenticated user."""
    yield create_test_user('authed@inveniosoftware.org')


# @pytest.fixture()
# def files_tmp_location(app, db):
#     try:
#         from invenio_files_rest.models import Location
#
#         loc = Location()
#         loc.name = 'test'
#         loc.uri = Path(tempfile.gettempdir()).as_uri()
#         loc.default = True
#         db.session.add(loc)
#         db.session.commit()
#     except ImportError:
#         pass


@pytest.yield_fixture()
def client(app, s3_location):
    """Get test client."""
    with app.test_client() as client:
        print(app.url_map)
        yield client

@pytest.fixture(scope='function')
def s3_bucket(appctx, base_app):
    """S3 bucket fixture."""
    with mock_s3():
        conn = boto3.resource('s3', region_name='us-east-1')
        # conn = boto3.resource('s3', region_name='us-east-1', endpoint_url=base_app.config['S3_ENDPOINT_URL'])
        # conn = boto3.resource('s3', region_name='storage',
        #                       endpoint_url=base_app.config['S3_ENDPOINT_URL'],
        #                       aws_access_key_id=base_app.config['S3_ACCESS_KEY_ID'],
        #                       aws_secret_access_key=base_app.config['S3_SECRET_ACCESS_KEY'])
        bucket = conn.create_bucket(Bucket='test_oarepo')

        yield bucket

        for obj in bucket.objects.all():
            obj.delete()
        bucket.delete()

@pytest.fixture(scope='function')
def s3_testpath(s3_bucket):
    """S3 test path."""
    return 's3://{}/'.format(s3_bucket.name)


@pytest.fixture(scope='function')
def s3storage(s3_testpath):
    """Instance of S3FileStorage."""
    s3_storage = S3FileStorage(s3_testpath)
    return s3_storage


@pytest.yield_fixture()
def s3_location(db, s3_testpath):
    """File system location."""
    loc = Location(
        name='testloc',
        uri=s3_testpath,
        default=True
    )
    db.session.add(loc)
    db.session.commit()

    yield loc

@pytest.fixture()
def sample_upload_data():
    key = 'testfile.dat'
    data = b'abcdefghijklmnop'
    data_size = str(len(data))
    fileinfo = {
        'key': key,
        'multipart_content_type': 'text/plain',
        'size': data_size
    }
    fileinfo_json = json.dumps(fileinfo)
    sample_upload_data = {
        'data': data,
        'fileinfo': fileinfo,
        'fileinfo_json': fileinfo_json
    }
    yield sample_upload_data


@pytest.fixture()
def draft_record(app, app_config, db, s3_location, s3_bucket, s3storage, prepare_es):
    """Minimal Record object."""
    record_uuid = uuid.uuid4()
    # SampleDraftRecord._prepare_schemas()
    dformat = '%Y-%m-%d'
    new_record = {
        "title": {"en":"example draft record"},
        "identifier": "test identifier",
        "created": datetime.utcnow().strftime(dformat),
        "modified": datetime.utcnow().strftime(dformat),
        "creator": "pytest creator"
        # '$schema': SampleDraftRecord.PREFERRED_SCHEMA
    }

    pid = record_pid_minter(record_uuid, data=new_record, pidstore_recid_field=app_config['PIDSTORE_RECID_FIELD'])
    record = TestRecord.create(data=new_record, id_=record_uuid)

    # RecordIndexer().index(record)
    # current_search_client.indices.refresh()
    # current_search_client.indices.flush()

    yield record


@pytest.fixture
def oartoken(db, draft_record):
    """OARepoToken fixture."""
    oartoken = OARepoAccessToken.create(
        rec_uuid = draft_record.id
    )
    # db.session.commit()
    yield oartoken


@pytest.fixture()
def test_blueprint(users, base_app):
    """Test blueprint with dynamically added testing endpoints."""
    blue = Blueprint(
        '_tests',
        __name__,
        url_prefix='/_tests/'
    )

    if blue.name in base_app.blueprints:
        del base_app.blueprints[blue.name]

    # for user in User.query.all():
    #     if base_app.view_functions.get('_tests.test_login_{}'.format(user.id)) is not None:
    #         del base_app.view_functions['_tests.test_login_{}'.format(user.id)]

        # blue.add_url_rule('_login_{}'.format(user.id), view_func=_test_login_factory(user))

    base_app.register_blueprint(blue)
    return blue

@pytest.fixture()
def prepare_es(app, db):
    """Prepare ES indices."""
    return

@pytest.fixture(scope='session')
def celery_config():
    """Celery worker config."""
    return {
        'result_backend': 'rpc',
        'task_always_eager': True
    }
