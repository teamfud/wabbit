# frozen_string_literal: true

require 'etc'

arm_host = Etc.uname[:version].include?('ARM64') ||
           RUBY_PLATFORM.include?('aarch64') ||
           RUBY_PLATFORM.include?('arm64')
box_arch = arm_host ? 'arm64' : 'amd64'
guest_target = arm_host ? 'aarch64-unknown-linux-gnu' : 'x86_64-unknown-linux-gnu'
artifact = File.expand_path("target/#{guest_target}/release/wabbit", __dir__)
abort("missing #{artifact}; run ./vm/build-artifact.sh first") unless File.file?(artifact)

Vagrant.configure('2') do |config|
  # The guest runs a host-built artifact. No source tree or compiler is
  # required in the VM.
  config.vm.synced_folder '.', '/vagrant', disabled: true

  {
    'ubuntu' => [
      arm_host ? 'cloudicio/ubuntu-server' : 'bento/ubuntu-22.04',
      '192.168.56.10',
      true
    ],
    'debian' => ['bento/debian-12', '192.168.56.11', false],
    'rocky' => ['bento/rockylinux-9', '192.168.56.12', false]
  }.each do |name, (box, ip, primary)|
    config.vm.define name, primary: primary, autostart: primary do |machine|
      machine.vm.box = box
      machine.vm.box_architecture = box_arch
      machine.vm.hostname = "wabbit-#{name}"
      machine.vm.network 'private_network', ip: ip
      machine.vm.provider 'virtualbox' do |vb|
        vb.name = "wabbit-#{name}"
        vb.memory = 4096
        vb.cpus = 2
        vb.customize ['modifyvm', :id, '--nested-hw-virt', 'on']
      end
      machine.vm.provision 'file', source: artifact, destination: '/tmp/wabbit'
      machine.vm.provision 'shell', path: 'vm/provision-kernel.sh'
    end
  end
end
