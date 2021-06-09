#!/bin/sh

echo $team_map | base64 -d > teammap.json

echo $s3_bucket_path

security-hub-collector -m teammap.json -s $s3_bucket_path