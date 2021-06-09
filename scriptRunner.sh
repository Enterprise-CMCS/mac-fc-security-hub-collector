#!/bin/sh

echo $team_map | base64 -d > teammap.json

security-hub-collector -m teammap.json -s $s3_bucket_path