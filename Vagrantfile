# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.provider :libvirt do |libvirt|
    libvirt.storage_pool_name = "home"
  end
  config.vm.box = "archlinux/archlinux"

  # Disable automatic box updates
  config.vm.box_check_update = false

  # For later communication with more nodes
  N = 1
  (1..N).each do |machine_id|
    config.vm.define "rootkit#{machine_id}" do |machine|
      machine.vm.hostname = "rootkit#{machine_id}"
      machine.vm.network "private_network", ip: "192.168.33.#{10+machine_id}"

      if machine_id == N
        machine.vm.provision :ansible do |ansible|
          ansible.limit = "all"
          ansible.groups = {
            "master" => ["rootkit1"],
            "workers" => ["rootkit[1:#{N}]"]
          }
          ansible.playbook = "provisioning/install.yaml"
        end
      end
    end
  end
end
