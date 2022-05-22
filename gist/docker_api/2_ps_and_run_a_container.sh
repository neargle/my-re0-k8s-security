#!/bin/bash

set -ue

docker -H "tcp://${docker_http_api}" ps
docker -H "tcp://${docker_http_api}" run -it -d alpine sleep infinity
docker -H "tcp://${docker_http_api}" ps

