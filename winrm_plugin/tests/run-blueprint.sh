#!/usr/bin/env bash

cfy local init -p winrm-script-blueprint.yaml --inputs ../inputs/script/input-good.yaml
cfy local execute -w install  --task-retries=10 --task-retry-interval=10
cfy local execute -w uninstall  --task-retries=10 --task-retry-interval=10