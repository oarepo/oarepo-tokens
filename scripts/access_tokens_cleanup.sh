#!/bin/bash

oarepo shell --simple-prompt -c "from oarepo_tokens.tasks import cleanup_expired_access_tokens; print(cleanup_expired_access_tokens())"
