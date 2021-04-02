#!/bin/bash

# create acme-srv.cfg if not existing
if [ ! -f /usr/local/est_proxy/data/est_proxy.cfg ] 
then 
    cp /usr/local/est_proxy/examples/est_proxy.cfg /usr/local/est_proxy/data/
fi

# create symlink for the acme_srv.cfg
if [ ! -L /usr/local/est_proxy/etc/est_proxy.cfg ]
then
    ln -s /usr/local/est_proxy/data/est_proxy.cfg /usr/local/est_proxy/etc/est_proxy.cfg
fi

exec "$@"

