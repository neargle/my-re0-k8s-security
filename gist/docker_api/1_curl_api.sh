#!/bin/bash

set -ue

curl -i "http://${docker_http_api}"
curl -i "http://${docker_http_api}/info"
