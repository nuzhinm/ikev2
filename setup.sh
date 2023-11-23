#!/bin/bash -e

echo
echo "=== Mikhail Nuzhin setting IKEv2-setup in Docker ==="
echo


function exit_badly {
  echo "$1"
  exit 1
}

IP=$(dig -4 +short myip.opendns.com @resolver1.opendns.com)

echo
echo "External IP: ${IP}"
echo

echo "*** This hostname must already resolve to this machine ***"
read -r -p "Hostname for VPN: " VPNHOST

VPNHOSTIP=$(dig -4 +short "${VPNHOST}")
[[ -n "$VPNHOSTIP" ]] || exit_badly "Cannot resolve VPN hostname: aborting"

if [[ "${IP}" != "${VPNHOSTIP}" ]]; then
  echo "Warning: ${VPNHOST} resolves to ${VPNHOSTIP}, not ${IP}"
  echo "Either you're behind NAT, or something is wrong (e.g. hostname points to wrong IP, CloudFlare proxying shenanigans, ...)"
  read -r -p "Press [Return] to continue anyway, or Ctrl-C to abort"
fi

read -r -p "VPN username: " VPNUSERNAME
while true; do
  read -r -s -p "VPN password (no quotes, please): " VPNPASSWORD
  echo
  read -r -s -p "Confirm VPN password: " VPNPASSWORD2
  echo
  [[ "${VPNPASSWORD}" = "${VPNPASSWORD2}" ]] && break
  echo "Passwords didn't match -- please try again"
done

