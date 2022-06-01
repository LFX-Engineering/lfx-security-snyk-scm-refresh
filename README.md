# lfx-security-snyk-scm-refresh

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
### Setup
Add dependencies
``` bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
Add the Snyk Scm tool
 ``` bash
 cd lfx-security-snyk-scm-refresh
 git clone git clone https://github.com/snyk-tech-services/snyk-scm-refresh.git
 ```

Add Module values that help adding the tool to the PYTHONPATH 

``` bash
cd snyk-scm-refresh
touch __init__.py
cat << 'EOF' > __init__.py
import common
from app import run
EOF

```


### Environment variables

```
export PYTHONPATH="$PWD:$PWD/snyk-scm-refresh"
export GITHUB_ENTERPRISE_HOST=<redacted>
export GITHUB_ENTERPRISE_TOKEN=<redacted>
export SNYK_TOKEN=<redacted>
```

### Run 
```
python main.py
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
