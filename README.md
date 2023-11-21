# ikev2 VPN server
ikev2 strongSwan VPN server with authorization by username and password EAP-MSCHAPv2 in a docker container.

The VPN server identifies itself with a Let's Encrypt certificate, so there's no need for clients to install private certificates — they can simply authenticate with username and strong password (EAP-MSCHAPv2).
### Before installation
You must have **docker, docker-compose, certbot** installed and a certificate from Let’s Encrypt.
Ports **500/udp and 4500/udp** must be open.

## How to install
Download the script and project files
````
git clone https://github.com/nuzhinm/ikev2
````
and set permissions to run the script
````
chmod +x ikev2/setup
````
Starting script execution
````
ikev2/setup
````

The script will start running and ask you to enter
1. your domain name
2. VPN server username
3. VPN server user password
4. VPN server user password confirmation

The script will edit the ipsec.conf ipsec.secrets and run files, start the creation of the Docker image and start the Docker container

**Ready**

You can connect with the data entered at the script stage.

## Adding and removing users
You can add and remove users by editing the **ipsec.secrets** file
````
nano ikev2/conf/ipsec.secrets
````
File data format `USERNAME : EAP PASSWORD`

For the server to pick up the changes, do
````
docker exec ikev2 ipsec secrets
````
You can also edit **ipsec.conf** To apply the changes, restart the container
````
docker restart ikev2
````

## How to connect
The script will create files for connecting clients along the path `ikev2/connect`
