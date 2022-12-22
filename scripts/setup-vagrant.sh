#!/bin/sh

IMAGE_DIR="/home/libvirt/images/"

sudo pacman -Syu vagrant ansible-core
vagrant plugin install vagrant-libvirt
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install community.general
sudo mkdir -p $IMAGE_DIR
sudo chmod 0711 $IMAGE_DIR
sudo setfacl --modify group:libvirt:rw- /home/libvirt/images/
virsh pool-define-as --name home --type dir --target $IMAGE_DIR
virsh pool-start home

