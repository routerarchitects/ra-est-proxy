#!/bin/bash

# create etc_proy default config to make sure that the container comes up
if [ ! -f /usr/local/est_proxy/data/est_proxy.cfg ]
then
    cp /usr/local/est_proxy/examples/est_proxy.cfg /usr/local/est_proxy/data/
    mkdir -p /usr/local/est_proxy/data/certs
    openssl req -x509 -newkey rsa:2048 -keyout /usr/local/est_proxy/data/certs/est-srv.key.pem -out /usr/local/est_proxy/data/certs/est-srv.crt.pem -days 30 -nodes -subj "/CN=est-proxy.est"
fi

# create symlink for the est_proxy.cfg
if [ ! -L /usr/local/est_proxy/etc/est_proxy.cfg ]
then
    ln -s /usr/local/est_proxy/data/est_proxy.cfg /usr/local/est_proxy/etc/est_proxy.cfg
fi

exec "$@"
