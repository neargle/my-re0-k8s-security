#!/bin/bash

set -ue

chroot /rootfs

ps auxf | grep kube
docker ps -a
