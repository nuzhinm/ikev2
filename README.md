# ikev2 VPN server
ikev2 strongSwan VPN server with authorization by username and password EAP-MSCHAPv2 in a docker container.
The VPN server identifies itself with a Let's Encrypt certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and strong password (EAP-MSCHAPv2).
