#!/bin/sh
set -eu

echo $TEAM_MAP | base64 -d > teammap.json

security-hub-collector -m teammap.json -s $S3_BUCKET_PATH