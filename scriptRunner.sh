#!/bin/sh

export team_map_decoded= echo $team_map | base64 -d

security-hub-collector -m $team_map_decoded -s $s3_bucket_path