#!/usr/bin/env python3

# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

import os
from typing import Any, Dict
from datetime import datetime
import psycopg2
from urllib.parse import urlparse


from app import run
import common

import click


env_list = ["GITHUB_ENTERPRISE_HOST", "SNYK_TOKEN"]


def connect(db_url):
    """Connect to the PostgreSQL database server"""
    conn = None
    try:
        # parse the db url
        parsed = urlparse(db_url)

        # connect to the PostgreSQL server
        print("Connecting to the PostgreSQL database...")
        conn = psycopg2.connect(
            database=parsed.path.strip("/"),
            user=parsed.username,
            password=parsed.password,
            host=parsed.hostname,
            port=parsed.port,
        )
        print("Connected...")
        return conn
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return


def validate_event(key, event_body, valid_data):
    if key in event_body and event_body[key] not in valid_data:
        return False
    return True


def validate_input(event_body: Dict[str, Any]) -> bool:
    fn = "validate_input"

    valid = True
    for env in env_list:
        if env not in os.environ:
            print(f"{fn}: missing {env} environment variable")
            valid = False
            break

    # Handle snyk-scm-refresh script args that take on [on,off] values
    valid_data = ["on", "off"]
    keys = ["iac", "container", "sca", "code"]
    for key in keys:
        if not validate_event(key, event_body, valid_data):
            print(f"{fn}: {key} options should be in {valid_data}")
            valid = False
            break

    if "github_auth_token" not in event_body:
        print(f"{fn} github_auth_token is empty")
        valid = False

    if "type" not in event_body:
        print(f"{fn} job_type is empty")
        valid = False

    if "project_sfid" not in event_body:
        print(f"{fn} project_sfid is empty")
        valid = False

    return valid


def parse_event(event_body):
    if event_body.get("snyk_organization_id"):
        common.ARGS.org_id = event_body.get("snyk_organization_id")
    if event_body.get("repository_id"):
        common.ARGS.repo_name = event_body.get("repository_id")
    if event_body.get("sca"):
        common.ARGS.sca = event_body.get("sca")
    if event_body.get("container"):
        common.ARGS.container = event_body.get("container")
    if event_body.get("iac"):
        common.ARGS.iac = event_body.get("iac")
    if event_body.get("code"):
        common.ARGS.code = event_body.get("code")
    if event_body.get("dry_run"):
        common.ARGS.dry_run = event_body.get("dry_run")
    if event_body.get("skip_scm_validation"):
        common.ARGS.skip_scm_validation = event_body.get("skip_scm_validation")
    if event_body.get("audit_large_repos"):
        common.ARGS.audit_large_repos = event_body.get("audit_large_repos")
    if event_body.get("debug"):
        common.ARGS.debug = event_body.get("debug")
    os.environ["GITHUB_ENTERPRISE_TOKEN"] = event_body.get("github_auth_token")


def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    start_time = datetime.now()
    fn = "lambda_handler"
    print(f"{fn} - received event: {event} with context: {context}")

    if "body" not in event:
        print(f"{fn} - received event with no body - unable to process message")
        return {}

    event_body = event["body"]
    print(f"{fn} - event : {event_body}")

    # Check the input - make sure we have everything
    if not validate_input(event_body):
        return {}

    cursor = None
    status = None
    pg_conn = None

    try:
        pg_conn = connect(os.environ.get("DATABASE_URL"))
        cursor = pg_conn.cursor()
        # populate snyk-scm-refresh command line args based on event data
        parse_event(event_body)

        # invoke the scm-refresh tool
        run()

        status = "invoked"

    except Exception as ex:
        print(f"{fn} - error: {ex}")
        status = f"invoked error - {ex}"

    if cursor:
        project_sfid = event_body.get("project_sfid")
        type = event_body.get("type")
        cursor.execute(
            "UPDATE public.scheduler_tasks SET status = (%s) WHERE project_sfid = (%s) and job_type =(%s)",
            (status, project_sfid, type),
        )
        pg_conn.commit()
        cursor.close()

    if pg_conn:
        pg_conn.close()
    print(f"Finished processing - duration: {datetime.now() - start_time}")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--org-id",
    is_flag=False,
    type=click.STRING,
    help="github organization identifier",
)
@click.option("--repo-name", is_flag=False, type=click.STRING, help="github repository name")
@click.option(
    "--sca",
    is_flag=False,
    type=click.Choice(["on", "off"]),
    help="scan for SCA manifests (on by default)",
    default="on",
)
@click.option(
    "--container",
    is_flag=False,
    type=click.Choice(["on", "off"]),
    help="can for container projects, e.g. Dockerfile (on by\
                        default)",
    default="on",
)
@click.option(
    "--iac",
    is_flag=False,
    type=click.Choice(["on", "off"]),
    help=" scan for IAC manifests (experimental, off by default)",
    default="on",
)
@click.option(
    "--code",
    is_flag=False,
    type=click.Choice(["on", "off"]),
    help="create code analysis if not present (experimental, off\
                        by default)",
    default="on",
)
@click.option("--dry-run", is_flag=True, help="flag to indicate if this is a dry run", default=False)
@click.option(
    "--skip-scm-validation", is_flag=True, help="Skip validation of the TLS certificate used by the SCM", default=False
)
@click.option(
    "--audit-large-repos",
    is_flag=True,
    help="only query github tree api to see if the response is\
                        truncated and log the result. These are the repos that\
                        would have be cloned via this tool",
    default=False,
)
@click.option(
    "--debug",
    is_flag=True,
    help="Write detailed debug data to snyk_scm_refresh.log for\
                        troubleshooting",
    default=False,
)
def main(org_id, repo_name, sca, container, iac, code, dry_run, skip_scm_validation, audit_large_repos, debug):
    # invoked from the command line

    event_data = {
        "sca": sca,
        "container": container,
        "iac": iac,
        "code": code,
        "dry_run": dry_run,
        "skip_scm_validation": skip_scm_validation,
        "audit_large_repos": audit_large_repos,
        "debug": debug,
        "github_auth_token": os.environ.get("GITHUB_ENTERPRISE_TOKEN"),
    }
    if org_id:
        event_data["org_id"] = org_id
    if repo_name:
        event_data["repo_name"] = repo_name
    event = {"body": event_data}
    context = {"function_name": "lfx-security-snyk-scm-refresh"}
    lambda_handler(event, context)


if __name__ == "__main__":
    import sys

    sys.exit(main())
