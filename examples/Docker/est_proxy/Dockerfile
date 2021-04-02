FROM ubuntu:20.04
LABEL maintainer="grindelsack@gmail.com"

RUN apt-get update
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install --no-install-recommends -y \
    python3-pip \
    curl \
    openssl \
 && rm -rf /var/lib/apt/lists/*

# install python requirements
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt


# create folders for acme2certifier
RUN mkdir -p /usr/local/est_proxy/etc && \
    mkdir -p /usr/local/est_proxy/examples && \
    mkdir -p /usr/local/est_proxy/bin
    
COPY est_proxy/ /usr/local/est_proxy/est_proxy
COPY examples/ca_handler/ /usr/local/est_proxy/examples/ca_handler
COPY examples/est_proxy.cfg /usr/local/est_proxy/examples/
COPY est_proxyd.py /usr/local/est_proxy/bin/est_proxyd.py
RUN chmod a+rx /usr/local/est_proxy/bin/est_proxyd.py

COPY examples/Docker/est_proxy/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod a+rx /docker-entrypoint.sh


WORKDIR /usr/local/est_proxy/

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python3", "/usr/local/est_proxy/bin/est_proxyd.py", "-c", "/usr/local/est_proxy/etc/est_proxy.cfg"]
# CMD ["sleep", "infinity"]

EXPOSE 17443 17443
