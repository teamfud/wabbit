# frozen_string_literal: true

require 'etc'

arm_host = Etc.uname[:version].include?('ARM64') ||
           RUBY_PLATFORM.include?('aarch64') ||
           RUBY_PLATFORM.include?('arm64')
box_arch = arm_host ? 'arm64' : 'amd64'
guest_target = arm_host ? 'aarch64-unknown-linux-musl' : 'x86_64-unknown-linux-musl'
artifact = File.expand_path("target/#{guest_target}/release/wabbit-initrd", __dir__)
abort("missing #{artifact}; run ./vm/build-artifact.sh first") unless File.file?(artifact)

Vagrant.configure('2') do |config|
  # The guest runs a host-built artifact. No source tree or compiler is
  # required in the VM. The artifact is the wabbit-initrd executable, built
  # static for musl: it embeds both the wabbit binary and the bnuuy eBPF
  # object, so it runs on any distro and in any initramfs.
  config.vm.synced_folder '.', '/vagrant', disabled: true

  # The target matrix. Boot one at a time (`vagrant up <name>`) to keep disk
  # and memory use down; boxes are only downloaded on first boot.
  {
    'ubuntu2404' => ['bento/ubuntu-24.04', '192.168.56.10', true],
    'ubuntu2204' => ['bento/ubuntu-22.04', '192.168.56.11', false],
    'debian12' => ['bento/debian-12', '192.168.56.12', false],
    'rocky9' => ['bento/rockylinux-9', '192.168.56.13', false]
  }.each do |name, (box, ip, primary)|
    config.vm.define name, primary: primary, autostart: primary do |machine|
      machine.vm.box = box
      machine.vm.box_architecture = box_arch
      machine.vm.hostname = "wabbit-#{name}"
      machine.vm.network 'private_network', ip: ip
      machine.vm.provider 'virtualbox' do |vb|
        vb.name = "wabbit-#{name}"
        vb.memory = 2048
        vb.cpus = 2
        vb.linked_clone = true
        vb.customize ['modifyvm', :id, '--nested-hw-virt', 'on']
      end
      machine.vm.provision 'file', source: artifact, destination: '/tmp/wabbit-initrd'
      machine.vm.provision 'shell', path: 'vm/provision-kernel.sh'
    end
  end
end