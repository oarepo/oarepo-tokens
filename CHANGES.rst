..
    Copyright (C) 2021 CESNET.

    OARepo-tokens is free software; you can redistribute it and/or
    modify it under the terms of the MIT License; see LICENSE file for more
    details.

Changes
=======

Version 0.1.0 (released TBD)
 - Initial public release.

Version 0.1.2
 - Create_token API call rewrited using oarepo-actions.

Version 0.1.3
 - revoke_token impl.
 - permissions for create_token action added
 - sleeps on calls w. invalid token added

Version 0.1.4
 - get_by_uuid returns all; disable token_detail

Version 0.1.5
 - pid_type test fixed

Version 0.1.6
 - versioning typo fixed

Version 0.1.7
 - added permission check on create_token
 - fix: used canonical_url instead of url_for

Version 0.1.8
 - oarepo-actions added to requires + flask ver.limited
 
