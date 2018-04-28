# Name: Trevor Philip
# Student number: nl10252
# Date: 4/14/2018
# Purpose: Installs the latest version of the Mono Runtime, which is needed for the userland process
# 	   This is based on the bash script provided here for Debian http://www.mono-project.com/docs/compiling-mono/linux/

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

PREFIX=$@
if [ -z $PREFIX ]; then
  PREFIX="~/.mono/"
fi

mkdir $PREFIX
chown -R `whoami` $PREFIX

apt-get install git autoconf libtool automake build-essential mono-devel gettext cmake

PATH=$PREFIX/bin:$PATH
git clone https://github.com/mono/mono.git
cd mono
./autogen.sh --prefix=$PREFIX
make
make install

