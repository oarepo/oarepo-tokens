# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 CESNET.
#
# OARepo-Tokens is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.

"""OArepo module that adds support for tokens"""

from invenio_db import db
from base32_lib import base32
from datetime import datetime, timedelta
from flask import current_app, url_for
from sqlalchemy.dialects import mysql
from sqlalchemy_utils.types import UUIDType
from invenio_records.models import Timestamp
from invenio_base.utils import load_or_import_from_config
from sqlalchemy_utils import EncryptedType
from invenio_pidstore.models import PersistentIdentifier, PIDStatus
from oarepo_records_draft import current_drafts
from oarepo_records_draft.types import RecordEndpointConfiguration

def _secret_key():
    """Return secret key from current application."""
    return current_app.config.get('SECRET_KEY')

class OARepoAccessToken(db.Model, Timestamp):
    """Model for storing tokens for CLI uploads.

    """

    __tablename__ = 'oarepo_tokens'

    __table_args__ = (
        db.Index('uidx_token', 'token', unique=True),
        db.Index('idx_rec_uuid', 'rec_uuid', unique=False),
    )

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    """Id of token."""

    token = db.Column(
        EncryptedType(type_in=db.Text, key=_secret_key), nullable=False
    )
    """Oarepo token"""

    rec_uuid = db.Column(UUIDType, nullable=False)
    """Persistent Identifier."""

    not_after = db.Column(
        db.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"),
        nullable=True
    )
    """Expiration in seconds."""

    def __repr__(self):
        """String representation for model."""
        dtformat = '%y%m%d-%H:%M:%S'
        return ('Oarepo Access Token <rec_uuid={0.rec_uuid} '
                'access_token=****{1} created={2} updated={3} not_after={4} status={5} '
                '>'.format(self, self.token[-4:],
                           self.created.strftime(dtformat),
                           self.updated.strftime(dtformat),
                           self.not_after.strftime(dtformat) if isinstance(self.not_after, datetime) else None,
                           self.get_status()
                    )
                )

    @classmethod
    def create(cls, rec_uuid):
        """Create a new CLI upload token

        :param rec_uuid: Record identifier value.
        :returns: A :class:`oarepo_tokens.models.OARepoAccessToken` instance.
        """
        ttl = load_or_import_from_config('OAREPO_TOKENS_TOKEN_TTL')
        with db.session.begin_nested():
            token=base32.generate(length=10, split_every=0, checksum=True)
            obj = cls(
                token=token,
                rec_uuid=rec_uuid,
                not_after=datetime.utcnow()+timedelta(seconds=ttl)
            )
            db.session.add(obj)
        db.session.commit()
        return obj

    @classmethod
    def get(cls, token_id):
        """Fetch a specific token object"""
        q = cls.query.filter_by(
            id=token_id
        )
        return q.one_or_none()


    @classmethod
    def get_by_uuid(cls, rec_uuid):
        """Fetch a specific token object"""
        q = cls.query.filter_by(
            rec_uuid=rec_uuid
        )
        return q.one_or_none()


    @classmethod
    def get_by_token(cls, token):
        """Fetch a specific token object"""
        q = cls.query.filter_by(
            token=token
        )
        return q.one()


    def get_record(self):
        """Fetch a linked record"""
        pids = PersistentIdentifier.query.filter(PersistentIdentifier.object_uuid==self.rec_uuid)
        rh, ra = {}, []
        for pid in pids:
            pid_pair = {'pid_type': pid.pid_type, 'pid_value': pid.pid_value}
            rh[pid.pid_type] = pid_pair
            ra.append(pid_pair)
        # pid_type = rh['drcid']['pid_type'] if rh['drcid'] else ra[0]['pid_type']
        pid_type = 'drcid' if rh['drcid'] else ra[0]['pid_type']
        endpoint: RecordEndpointConfiguration = current_drafts.endpoint_for_pid_type(pid_type)
        rec = endpoint.record_class.get_record(self.rec_uuid)
        rec['init_upload'] = url_for('oarepo_records_draft.draft-record_files',
                                        pid_value=rec['id'], _external=True, multipart='true')
        rec['files'] = url_for('oarepo_records_draft.draft-record_files',
                                        pid_value=rec['id'], _external=True)
        return rec


    @classmethod
    def query_expired(cls, dt, token=None):
        """Query expired tokens."""
        q = cls.query.filter(cls.not_after < dt)
        if token:
            q = q.filter(cls.token == token)
        return q.all()

    @classmethod
    def delete_expired(cls, dt, token=None):
        """Delete expired tokens."""
        toks = cls.query_expired(dt, token)
        for tok in toks:
            db.session.delete(tok)
        db.session.commit()

    def revoke(self):
        """revoke token."""
        self.not_after = datetime.utcnow()
        db.session.commit()

    def is_valid(self):
        return self.not_after > datetime.utcnow()

    def get_status(self):
        return 'OK' if self.is_valid() else 'Expired'

    def to_json(self, filter_out=None, dtformat='%y%m%d-%H:%M:%S'):
        d = dict(
            id=self.id,
            token=self.token,
            rec_uuid=self.rec_uuid,
            created=self.created.strftime(dtformat),
            updated=self.updated.strftime(dtformat),
            not_after=self.not_after.strftime(dtformat),
        )
        if filter_out is not None:
            for i in filter_out:
                del d[i]
        return d
