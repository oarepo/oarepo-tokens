# oarepo-tokens

[![][license_badge]][license]
[![][status_badge]][actions]
[![][pypi_badge]][pypi_url]

OARepo library generating tokens for upload from command-line utility [oarepo-s3-cli](https://github.com/oarepo/oarepo-s3-cli/)

## Installation
  TBD

## Configuration
  TBD

## API
  * **POST /access-tokens/status**

    Returns status of token sent in auth.header.


  * POST /access-tokens/revoke

    Revoke token sent in auth.header.


  * POST /<DRAFT_RECORD_PATH>/create_token

    Create new token for upload file to draft record.


  * GET /<DRAFT_RECORD_PATH>/access-tokens

    List tokens created for uploading to draft record.


  * DELETE /<DRAFT_RECORD_PATH>/access-tokens/<TOKEN_ID>

    Revoke token by token_id.


  [license_badge]: https://img.shields.io/github/license/oarepo/oarepo-tokens.svg "license badge"
  [license]: https://github.com/oarepo/oarepo-tokens/blob/master/LICENSE "license text"
  [status_badge]: https://github.com/oarepo/oarepo-tokens/actions/workflows/main.yml/badge.svg "status badge"
  [actions]: https://github.com/oarepo/oarepo-tokens/actions/ "actions"
  [pypi_badge]: https://img.shields.io/pypi/v/oarepo-tokens.svg "pypi badge"
  [pypi_url]: https://pypi.org/pypi/oarepo-tokens "pypi url"
