#!/bin/sh
set -eu

echo $TEAM_MAP | base64 -d > teammap.json

echo "Beginning Collector"

security-hub-collector \
  -m teammap.json \
  ${OUTPUT:+-o "$OUTPUT"} \
  ${S3_KEY:+-k "$S3_KEY"} \
  ${ASSUME_ROLE:+-a "$ASSUME_ROLE"}

security-hub-collector \
  -u \
  -s $S3_BUCKET_PATH \
  ${S3_KEY:+-k "$S3_KEY"} \
  ${OUTPUT:+-o "$OUTPUT"}

echo "Task complete"