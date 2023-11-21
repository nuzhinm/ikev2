FROM ubuntu:22.04

ADD ikev2/bin/* /usr/bin/

RUN apt-get -o Acquire::ForceIPv4=true update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y install nano tzdata iptables-persistent strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins libcharon-extauth-plugins \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x /usr/bin/run

ADD ikev2/conf/* /etc/

CMD /usr/bin/run