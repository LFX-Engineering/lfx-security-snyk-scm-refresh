# LFX Security Snyk SCM Refresh Lambda

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build PR](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/workflows/Build%20and%20Test%20Pull%20Request/badge.svg)](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/actions)
[![Build PR](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/workflows/Snyk%20Scan/badge.svg)](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/actions)
[![Build PR](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/workflows/Yarn%20Dependency%20Audit/badge.svg)](https://github.com/LFX-Engineering/lfx-security-snyk-scm-refresh/actions)

This is a wrapper lambda for the [Snyk SCM refresh python tool](https://github.com/snyk-tech-services/snyk-scm-refresh) which cleans up the Snyk projects after a successful scan.

The Snyk SCM tool keeps Snyk projects in sync with their associated Github repos.

For repos with at least 1 project already in Snyk:

- Detect and import new manifests
- Remove projects for manifests that no longer exist
- Update projects when a repo has been renamed
- Detect and update default branch change (not renaming)
- Enable Snyk Code analysis for repos
- Detect deleted repos and log for review

## Prerequisites
Python3.7 

## Deployment

```bash
yarn deploy:dev
```

## Command Line Testing

```bash
# First: Log into your AWS account for the appropriate environment
# Second: invoke using the desired payload, ensure github_enterprise_token, one can add extra params like repo_name, org_id for 
aws --region us-east-2 lambda invoke \
  --function-name lfx-security-snyk-scm-refresh \
  --cli-binary-format raw-in-base64-out \
  --payload '{"github_enterprise_token":"XXXX","repo_name":"easycla...","org_id":"org"}' \
```


## References

- [Snyk SCM Refresh Python Module](https://github.com/snyk-tech-services/snyk-scm-refresh)
- [LFX Security API](https://github.com/LF-Engineering/lfx-security)
- [LFX Security UI/Console](https://github.com/LFX-Engineering/lfx-security-ui)
- [LFX Security BFF](https://github.com/LFX-Engineering/lfx-security-bff)

## License

Copyright The Linux Foundation and each contributor to LFX.

This project’s source code is licensed under the MIT License. A copy of the license is available in LICENSE.

The project leverages source code from the [Open Source Security Foundation's (OSSF) - Criticality
Score](https://github.com/ossf/criticality_score), which is licensed under the Apache License, version 2.0
\(Apache-2.0\),

This project’s documentation is licensed under the Creative Commons Attribution 4.0 International License \(CC-BY-4.0\).
A copy of the license is available in LICENSE-docs.
