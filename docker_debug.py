__all__ = ['DockerDebug']
import tempfile
import docker
import pwnlib
import paramiko
import os
import threading


class DockerDebug():
    def __init__(self, os_name, remote_shell=None):
        '''
        os_name:
            ubuntu-1604
            ubuntu-1704
            ubuntu-1804
        remote_shell: shell in remote docker host server.
        '''
        self.docker_shell = None
        self.remote_shell = None
        self.gdbserver_addr = None

        if remote_shell is not None:
            if isinstance(remote_shell, pwnlib.tubes.ssh.ssh):
                self.remote_shell = remote_shell
                docker_client = docker.DockerClient(base_url='unix:{}/remote_docker.sock'.format(os.getenv('HOME')))
            else:
                raise TypeError('remote_shell must be pwnlib.tubes.ssh.ssh')
        else:
            docker_client = docker.from_env()

        container_name = 'pwn-environment-{}'.format(os_name)
        ip = docker_client.api.inspect_container(container_name)['NetworkSettings']['Networks']['pwn-environment']['IPAddress']
        port = 22

        # if using remote docker, start port forwarding
        # if self.remote_shell is not None:
        #     l = pwnlib.tubes.listen.listen(0)
        #     l.wait_for_connection().connect_both(self.remote_shell.connect_remote(ip, 22))
        #     ip = 'localhost'
        #     port = l.lport
        # else:
        #     port = 22

        try:
            self.docker_shell = pwnlib.tubes.ssh.ssh('root', ip, port, password='')
        except paramiko.BadHostKeyException:
            os.system('ssh-keygen -f "${{HOME}}/.ssh/known_hosts" -R "{}"'.format(ip))
            self.docker_shell = pwnlib.tubes.ssh.ssh('root', ip, password='')
        self.docker_shell.set_working_directory(b'/binary')

    def __del__(self):
        if self.docker_shell is not None:
            self.docker_shell.close()

    def process(self, *args, **kwargs):
        return self.docker_shell.process(*args, **kwargs)

    def attach(self, target, gdbscript='', port=None):
        host = self.docker_shell.host
        if port is None:
            port = 50818
        gdbscript = 'target extended-remote {}:{}\nattach {}\n{}'.format(host, port, target.pid, gdbscript)
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',delete = False, mode = 'w+')
        gdbscript = 'shell rm {}\n{}'.format(tmp.name, gdbscript)
        tmp.write(gdbscript)
        tmp.close()
        cmd = 'gdb -q -x "{}"'.format(tmp.name)
        pwnlib.util.misc.run_in_new_terminal(cmd)



# rm -f ./remote_docker.sock && ssh -fnNTL ./remote_docker.sock:/var/run/docker.sock -o StreamLocalBindUnlink=yes hyperv-debian




