__all__ = ['process', 'set_os', 'attach']
import tempfile
import docker
import pwnlib
import paramiko
import os

# init docker connect
docker_client = docker.from_env()
os_name = None
docker_shell = None

def process(*args, **kwargs):
    return docker_shell.process(*args, **kwargs)


def set_os(os_name):
    global docker_shell
    if docker_shell is not None:
        docker_shell.close()
    container_name = 'pwn-environment-{}'.format(os_name)
    ip = docker_client.api.inspect_container(container_name)['NetworkSettings']['Networks']['pwn-environment']['IPAddress']
    try:
        docker_shell = pwnlib.tubes.ssh.ssh('root', ip, password='')
    except paramiko.BadHostKeyException:
        os.system('ssh-keygen -f "${{HOME}}/.ssh/known_hosts" -R "{}"'.format(ip))
        docker_shell = pwnlib.tubes.ssh.ssh('root', ip, password='')
    docker_shell.cwd = '/binary'

def attach(target, gdbscript='', host=None, port=None):
    host = docker_shell.host
    port = 50818
    gdbscript = 'target extended-remote {}:{}\nattach {}\n{}'.format(host, port, target.pid, gdbscript)
    tmp = tempfile.NamedTemporaryFile(prefix = 'pwn', suffix = '.gdb',delete = False, mode = 'w+')
    gdbscript = 'shell rm {}\n{}'.format(tmp.name, gdbscript)
    tmp.write(gdbscript)
    tmp.close()
    cmd = 'gdb -q -x "{}"'.format(tmp.name)
    pwnlib.util.misc.run_in_new_terminal(cmd)

