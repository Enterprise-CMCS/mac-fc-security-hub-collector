#!/bin/sh
set -eu

echo $TEAM_MAP | base64 -d > teammap.json

echo "Beginning Collector"

security-hub-collector \
  -m teammap.json \
  ${OUTPUT:+-o "$OUTPUT"} \
  ${S3_KEY:+-k "$S3_KEY"} \
  ${S3_BUCKET_PATH:+-b "$S3_BUCKET_PATH"}

echo "Task complete"
