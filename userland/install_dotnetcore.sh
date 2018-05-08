# Name: Trevor Philip
# Student ID: NL10252
# Date: 5/3/2018
# CMSC 421 Spring 2018
# Purpose: Installs DotNet Core SDK and dependencies needed for the intrusion detection system. Commands
#          are based on https://www.microsoft.com/net/download/linux-package-manager/debian9/sdk-current

#if [[ $EUID -ne 0 ]]; then
#   echo "This script must be run as root user!"
#   exit 1
#fi

apt-get update
apt-get install apt-transport-https

wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg;
mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/;
wget -q https://packages.microsoft.com/config/debian/9/prod.list;
mv prod.list /etc/apt/sources.list.d/microsoft-prod.list;

apt-get update
apt-get install dotnet-sdk-2.1.105

