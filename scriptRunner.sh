#!/bin/sh
set -eu

echo $TEAM_MAP | base64 -d > teammap.json

echo "Beginning Collector"

security-hub-collector \
  -m teammap.json \
  -s $S3_BUCKET_PATH \
  ${OUTPUT:+-o "$OUTPUT"} \
  ${S3_KEY:+-k "$S3_KEY"}

echo "Task complete"