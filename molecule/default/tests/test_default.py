import os

import testinfra.utils.ansible_runner

testinfra_hosts = testinfra.utils.ansible_runner.AnsibleRunner(
    os.environ['MOLECULE_INVENTORY_FILE']).get_hosts('all')


def test_openssh_server_is_installed(host):
    ssh = host.package("openssh-server")

    assert ssh.is_installed


def test_sshd_config(host):
    cmd = host.run("sshd -T")

    assert 'passwordauthentication no' in cmd.stdout
    assert 'permitrootlogin no' in cmd.stdout
    assert 'x11forwarding no' in cmd.stdout
    assert """kexalgorithms curve25519-sha256@libssh.org,
    diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,
    diffie-hellman-group14-sha256' in cmd.stdout"""
    assert """chiphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,
    aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"""
    assert """macs umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,
    hmac-sha2-512-etm@openssh.com"""
