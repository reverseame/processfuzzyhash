#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Root required"
    exit
fi

# System dependencies
echo -e "\n[*] Installing system dependencies...\n"
systemdeps="python2.7 python2.7-dev python2.7-pip ssdeep libfuzzy-dev git cmake libffi-dev libssl1.0.0 build-essential"
echo -e "[*] Adding jessie-backports repository to source packages...\n"
sudo cp jessie-backports.list /etc/apt/sources.list.d
echo -e "[*] Updating list of available packages...\n"
sudo apt-get update
echo -e "\n[*] Installing system dependencies...\n"
sudo apt-get install -y $systemdeps

# Python2 dependencies
echo -e "\n[*] Installing Python2 dependencies...\n"
pythondeps="pycrypto distorm3 pefile ssdeep fuzzyhashlib"
sudo pip2 install $pythondeps

echo -e "\n[*] Installing TSLH manually...\n"
git clone "https://github.com/trendmicro/tlsh.git" /tmp/tlsh/
oldpwd=$(pwd)
cd /tmp/tlsh/
./make.sh
cd py_ext
python2 setup.py build
sudo python2 setup.py install
cd $oldpwd
rm -rf /tmp/tlsh/

echo -e "\nDone!"
