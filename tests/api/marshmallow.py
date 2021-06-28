from marshmallow import Schema, fields, validate, INCLUDE
# from invenio_records_rest.schemas import StrictKeysMixin
# from oarepo_dc.marshmallow import DCObjectSchemaV2Mixin
# from oarepo_invenio_model.marshmallow import InvenioRecordMetadataSchemaV1Mixin, \
#     InvenioRecordMetadataFilesMixin
from oarepo_multilingual.marshmallow import MultilingualStringV2

class SampleSchemaV1(Schema):
    # InvenioRecordMetadataFilesMixin,
    # InvenioRecordMetadataSchemaV1Mixin,
    # DCObjectSchemaV2Mixin,
    # StrictKeysMixin
    # title = fields.String(validate=validate.Length(min=5), required=True)
    title = MultilingualStringV2(required=True)
    pass

    class Meta:
        unknown = INCLUDE
