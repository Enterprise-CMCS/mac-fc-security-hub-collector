#!/bin/sh

export team_map_decoded=$(base64 -d $team_map)

security-hub-collector -m $team_map_decoded -s $s3_bucket_path