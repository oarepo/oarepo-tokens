# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""
import uuid
from collections import namedtuple

import flask
from flask import current_app, url_for
from flask_security import login_user
# from marshmallow.fields import URL, Integer, Nested
from invenio_accounts.models import User
from invenio_indexer.api import RecordIndexer
# from invenio_records import Record
from invenio_records_files.api import Record
from oarepo_records_draft.record import DraftRecordMixin
from werkzeug.local import LocalProxy
# from marshmallow import INCLUDE, Schema
from invenio_pidstore.providers.recordid import RecordIdProvider
from oarepo_validate import MarshmallowValidatedRecordMixin, SchemaKeepingRecordMixin
from oarepo_references.mixins import InlineReferenceMixin, ReferenceByLinkFieldMixin, ReferenceEnabledRecordMixin
from invenio_records_rest.schemas.fields import SanitizedUnicode
from invenio_records_rest.utils import allow_all, deny_all

#from oarepo_tokens.api import OARepoCommunity
from oarepo_tokens.models import OARepoAccessToken
from oarepo_tokens.permissions import put_file_token_permission_factory
from oarepo_tokens.views import TokenEnabledDraftRecordMixin
from .constants import SAMPLE_ALLOWED_SCHEMAS, SAMPLE_PREFERRED_SCHEMA
from .marshmallow import SampleSchemaV1

_datastore = LocalProxy(lambda: current_app.extensions['security'].datastore)


def gen_rest_endpoint(pid_type, search_class, record_class, permission_factory=None):
    return dict(
        draft='draft-record',
        pid_type=pid_type,
        pid_minter=pid_type,
        pid_fetcher=pid_type,
        search_class=search_class,
        indexer_class=TestIndexer,
#        links_factory_imp=community_record_links_factory,
        search_index='records-record-v1.0.0',
        search_type='_doc',
        record_class=record_class,
#        record_loaders={
#            'application/json': 'oarepo_communities.loaders:community_json_loader',
#        },
        record_serializers={
            'application/json': ('invenio_records_rest.serializers'
                                 ':json_v1_response'),
        },
        search_serializers={
            'application/json': ('invenio_records_rest.serializers'
                                     ':json_v1_search'),
        },
        list_route='/records/',
        item_route='/records/<pid(drcid,'
                      f'record_class="{record_class}")'
                      ':pid_value>',
        default_media_type='application/json',
        max_result_window=10000,
        error_handlers=dict(),
        read_permission_factory_imp=permission_factory,
        create_permission_factory_imp=permission_factory,
        update_permission_factory_imp=permission_factory,
        delete_permission_factory_imp=permission_factory,
        files=dict(
            put_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
            get_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
            delete_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
        ),
    )

def gen_rest_endpoint_draft(pid_type, search_class, record_class, permission_factory=None):
    return dict(
        pid_type=pid_type,
        pid_minter=pid_type,
        pid_fetcher=pid_type,
        search_class=search_class,
        indexer_class=TestIndexer,
#        links_factory_imp=community_record_links_factory,
        search_index='draft-records-record-v1.0.0',
        search_type='_doc',
        record_class=record_class,
#        record_loaders={
#            'application/json': 'oarepo_communities.loaders:community_json_loader',
#        },
        record_serializers={
            'application/json': ('invenio_records_rest.serializers'
                                 ':json_v1_response'),
        },
        search_serializers={
            'application/json': ('invenio_records_rest.serializers'
                                 ':json_v1_search'),
        },
        list_route='/draft/records/',
        item_route='/draft/records/<pid(drcid,'
                      f'record_class="{record_class}")'
                      ':pid_value>',
        default_media_type='application/json',
        max_result_window=10000,
        error_handlers=dict(),
        read_permission_factory_imp=allow_all,
        create_permission_factory_imp=permission_factory,
        update_permission_factory_imp=permission_factory,
        delete_permission_factory_imp=permission_factory,
        files=dict(
            put_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
            get_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
            delete_file_factory=put_file_token_permission_factory(default_permission_factory=permission_factory),
        ),
    )


def make_sample_token(uuid):
    oartoken = OARepoAccessToken.create(
        rec_uuid=uuid
    )
    return oartoken


def _test_login_factory(user):
    def test_login():
        login_user(user, remember=True)
        return 'OK'

    test_login.__name__ = '{}_{}'.format(test_login.__name__, user.id)
    return test_login

def record_pid_minter(record_uuid, data, pidstore_recid_field='id'):
    """Mint loan identifiers."""
    assert "pid" not in data
    provider = RecordIdProvider.create(
        pid_type='drcid',
        object_type='rec',
        object_uuid=record_uuid,
    )
    data[pidstore_recid_field] = provider.pid.pid_value
    return provider.pid

# class TaxonomySchema(InlineReferenceMixin, Schema):
#     """Taxonomy schema."""
#
#     class Meta:
#         unknown = INCLUDE
#
#     def ref_url(self, data):
#         return data.get('links').get('self')
#
#
# class NestedTaxonomySchema(Schema):
#     """Nested Taxonomy schema."""
#     taxo2 = Nested(TaxonomySchema, required=False)
#
# class URLReferenceField(ReferenceByLinkFieldMixin, URL):
#     """URL reference marshmallow field."""
#
# class URLReferenceSchema(Schema):
#     """Schema for an URL reference."""
#     title = SanitizedUnicode()
#     ref = URLReferenceField(data_key='$ref', name='$ref', attribute='$ref')
#
#
# class TestSchema(Schema):
#     """Test record schema."""
#     title = SanitizedUnicode()
#     pid = Integer()
#     taxo1 = Nested(TaxonomySchema, required=False)
#     sub = Nested(NestedTaxonomySchema, required=False)
#     ref = URLReferenceField(data_key='$ref', name='$ref', attribute='$ref', required=False)
#     reflist = Nested(URLReferenceSchema, many=True, required=False)
#     _bucket = SanitizedUnicode()
#     # oarepo:draft = Integer()

class TestIndexer(RecordIndexer):
    """Fake record indexer."""

    def index(self, record, arguments=None, **kwargs):
        return {}

class TestRecord(MarshmallowValidatedRecordMixin,
                DraftRecordMixin,
                # SchemaKeepingRecordMixin,
                ReferenceEnabledRecordMixin,
                TokenEnabledDraftRecordMixin,
                Record):
    """Token enabled test record class."""
    __test__ = False
    # ALLOWED_SCHEMAS = SAMPLE_ALLOWED_SCHEMAS
    ALLOWED_SCHEMAS = ['sample/sample-v1.0.0.json']
    # PREFERRED_SCHEMA = SAMPLE_PREFERRED_SCHEMA
    # MARSHMALLOW_SCHEMA = TestSchema
    MARSHMALLOW_SCHEMA = SampleSchemaV1
    VALIDATE_MARSHMALLOW = True
    VALIDATE_PATCH = True
    # CREATE_TOKEN_PERMISSION = allow_all

    @property
    def canonical_url(self):
        return url_for('invenio_records_rest.draft-record_item',
                       pid_value=self['id'], _external=True)
