#!/usr/bin/env bash

sudo docker stop qaim-be
sudo docker rm qaim-be
sudo docker rmi qaim-be-image
y | sudo docker container prune
y | sudo docker image prune
cp /etc/letsencrypt/live/api.qaim.finance/fullchain.pem ./
cp /etc/letsencrypt/live/api.qaim.finance/privkey.pem ./
sudo docker build . -t qaim-be-image
rm *.pem