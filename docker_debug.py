__all__ = ['DockerDebug']
import tempfile
import docker
import pwnlib
import paramiko
import os
import threading
import asyncio, asyncssh
from pwn import log

event_loop = asyncio.new_event_loop()

def event_loop_fun():
    asyncio.set_event_loop(event_loop)
    event_loop.run_forever()

event_loop_thread = threading.Thread(target=event_loop_fun)
event_loop_thread.setDaemon(True)
event_loop_thread.start()

class DockerDebug():
    def __init__(self, os_name, remote_host=None):
        '''
        os_name:
            ubuntu-1604
            ubuntu-1704
            ubuntu-1804
        remote_host: shell in remote docker server host.
        '''
        self.docker_shell = None
        self.remote_host = None
        self.gdbserver_port = 50818
        self.ssh_port = 22
        self.__unix_listener = None
        self.__ssh_listener = None
        self.__gdbserver_listener = None


        if remote_host is not None:
            if isinstance(remote_host, str):
                self.remote_host = remote_host
                docker_client = docker.DockerClient(base_url='unix:{}/remote_docker.sock'.format(os.getenv('HOME')))
            else:
                raise TypeError('remote_host must be str')
        else:
            docker_client = docker.from_env()

        container_name = 'pwn-environment-{}'.format(os_name)
        ip = docker_client.api.inspect_container(container_name)['NetworkSettings']['Networks']['pwn-environment']['IPAddress']


        # if using remote docker, start port forwarding
        if self.remote_host is not None:
            ip = '127.0.0.1'
            log.info("Wait port forwarding...")
            task = asyncio.run_coroutine_threadsafe(self.__ssh_forward(remote_host, ip), event_loop)
            while self.__gdbserver_listener is None:
                pass

        try:
            self.docker_shell = pwnlib.tubes.ssh.ssh('root', ip, self.ssh_port, password='')
        except paramiko.BadHostKeyException:
            os.system('ssh-keygen -f "${{HOME}}/.ssh/known_hosts" -R "{}"'.format(ip))
            self.docker_shell = pwnlib.tubes.ssh.ssh('root', ip, password='')
        self.docker_shell.set_working_directory(b'/binary')


    def __del__(self):
        if self.docker_shell is not None:
            self.docker_shell.close()
        if self.remote_host is not None:
            self.__unix_listener.close()
            self.__ssh_listener.close()
            self.__gdbserver_listener.close()
            asyncio.run_coroutine_threadsafe(asyncio.sleep(0), event_loop)


    def process(self, *args, **kwargs):
        return self.docker_shell.process(*args, **kwargs)


    def attach(self, target, gdbscript=''):
        host = self.docker_shell.host
        gdbscript = 'target extended-remote {}:{}\nattach {}\n{}'.format(host, self.gdbserver_port, target.pid, gdbscript)
        tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',delete = False, mode = 'w+')
        gdbscript = 'shell rm {}\n{}'.format(tmp.name, gdbscript)
        tmp.write(gdbscript)
        tmp.close()
        cmd = 'gdb -q -x "{}"'.format(tmp.name)
        pwnlib.util.misc.run_in_new_terminal(cmd)


    async def __ssh_forward(self, host, docker_ip):
        async with asyncssh.connect(host) as conn:
            self.__unix_listener = await conn.forward_local_path(os.getenv('HOME') + '/remote_docker.sock', '/var/run/docker.sock')
            self.__ssh_listener = await conn.forward_local_port('localhost', 0, docker_ip, 22)
            self.__gdbserver_listener = await conn.forward_local_port('localhost', 0, docker_ip, 50818)

            ssh_port = self.__ssh_listener.get_port()
            log.info("ssh: {}:{} -> localhost:{}".format(docker_ip, self.ssh_port, ssh_port))
            self.ssh_port = ssh_port

            gdbserver_port = self.__gdbserver_listener.get_port()
            log.info("gdbserver: {}:{} -> localhost:{}".format(docker_ip, self.gdbserver_port, gdbserver_port))
            self.gdbserver_port = gdbserver_port

            await self.__unix_listener.wait_closed()
            await self.__ssh_listener.wait_closed()
            await self.__gdbserver_listener.wait_closed()

            log.info('close port forwarding')




