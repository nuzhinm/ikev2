FROM ubuntu:22.04

RUN TZ=Europe/Moscow

RUN apt-get -o Acquire::ForceIPv4=true update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install iptables-persistent uuid-runtime strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins libcharon-extauth-plugins \
    && rm -rf /var/lib/apt/lists/*

ADD ./bin/* /usr/bin/

RUN chmod +x /usr/bin/run

CMD /usr/bin/run