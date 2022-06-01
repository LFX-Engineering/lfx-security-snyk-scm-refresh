#!/usr/bin/env python3

# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

import datetime
import json
import os
import re
from typing import Any, Dict, Optional
from datetime import datetime
import click


from app import run
import common


env_list = ['GITHUB_ENTERPRISE_HOST', 'GITHUB_ENTERPRISE_TOKEN', 'SNYK_TOKEN']

def validate_event(key, event_body, valid_data):
    if key in event_body and event_body[key] not in valid_data:
        return False
    return True

def validate_input(event_body: Dict[str, Any]) -> bool:
    fn = 'validate_input'

    valid = True
    for env in env_list:
        if env not in os.environ:
            print(f'{fn}: missing {env} environment variable')
            valid = False
            break
        
    # Handle snyk-scm-refresh script args that take on [on,off] values
    valid_data = ["on", "off"]
    keys = ["iac", "container", "sca", "code"]
    for key in keys:
        if not validate_event(key, event_body, valid_data):
            print(f'{fn}: {key} options should be in {valid_data}')
            valid = False
            break
    return valid

def parse_event(event_body):
    if event_body.get('org_id'):
        common.ARGS.org_id = event_body.get('org_id')
    if event_body.get('repo_name'):
        common.ARGS.repo_name = event_body.get('repo_name')
    if event_body.get('sca'):
        common.ARGS.sca = event_body.get('sca')
    if event_body.get('container'):
        common.ARGS.container = event_body.get('container')
    if event_body.get('iac'):
        common.ARGS.iac = event_body.get('iac')
    if event_body.get('code'):
        common.ARGS.code = event_body.get('code')
    if event_body.get('dry_run'):
        common.ARGS.dry_run = event_body.get('dry_run')
    if event_body.get('skip_scm_validation'):
        common.ARGS.skip_scm_validation = event_body.get('skip_scm_validation')
    if event_body.get('audit_large_repos'):
        common.ARGS.audit_large_repos = event_body.get('audit_large_repos')
    if event_body.get('debug'):
        common.ARGS.debug = event_body.get('debug')


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    start_time = datetime.now()
    fn = 'lambda_handler'
    print(f'{fn} - received event: {event} with context: {context}')

    if 'body' not in event:
        print(f'{fn} - received event with no body - unable to process message')
        return {}

    event_body = json.loads(event['body'])
    print(f'{fn} - event {type(event_body)}: {event_body}')

    # Check the input - make sure we have everything
    if not validate_input(event_body):
        return {}

    try:
        #populate snyk-scm-refresh command line args based on event data 
        parse_event(event_body)

        # invoke the scm-refresh tool
        run()
    except Exception as ex:
        print(f'{fn} - error: {ex}')
    
    print(f'Finished processing - duration: {datetime.now() - start_time}')

def main():
    # invoked from the command line
    event = {
        'body': '{"org_id": "033c4e75-4881-4787-8e84-c7cc3bed4620"}'
    }
    context = {
        "function_name": "lfx-security-snyk-scm-refresh"
    }
    lambda_handler(event, context)


if __name__ == "__main__":
    main()
