__all__ = ['DockerDebug', 'binary_path']


import tempfile
import paramiko
import os
import socket
import shutil
from pwnlib.util import misc
from pwnlib.tubes.ssh import ssh, ssh_process

binary_path = os.path.join(os.path.dirname(
    os.path.abspath(os.readlink(__file__))), 'binary')


def should_copy(src: str, dst: str) -> bool:
    if not os.path.exists(src):
        return False
    try:
        src_size = os.path.getsize(src)
        dst_size = os.path.getsize(dst)
    except FileNotFoundError:
        return True
    return src_size != dst_size


class DockerDebug():
    def __init__(self, os_name):
        '''
        os_name:
            ubuntu-1604
            ubuntu-1704
            ubuntu-1804
        '''
        self.container_name = 'pwn-environment-{}'.format(os_name)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        print(os.path.join(
            binary_path, 'socket', '{}-ssh'.format(self.container_name)))
        sock.connect(os.path.join(
            binary_path, 'socket', '{}-ssh'.format(self.container_name)))

        try:
            self.ssh = ssh(user='root', host=self.container_name,
                           password="", proxy_sock=sock)
        except paramiko.BadHostKeyException:
            os.system(
                'ssh-keygen -f "${{HOME}}/.ssh/known_hosts" -R "{}"'.format(self.container_name))
            self.ssh = ssh(user='root', host=self.container_name,
                           password="", proxy_sock=sock)
        self.ssh.set_working_directory(b'/binary')
        self.tmp_dir = tempfile.TemporaryDirectory(prefix='pwn', suffix='.gdb')

    def __del__(self):
        self.tmp_dir.cleanup()
        self.ssh.close()

    def process(self, *args, setuid=False, **kwargs) -> ssh_process:
        if len(args) > 0:
            argv = args[0]
        else:
            argv = kwargs['argv']

        if isinstance(argv, list) and len(argv) > 0:
            path: str = argv[0]
        elif isinstance(argv, str):
            path: str = argv
        else:
            raise Exception("argv must str or list")

        if path.startswith('./'):
            if not os.path.exists(path) and not os.path.exists(os.path.join(binary_path, path)):
                raise FileNotFoundError("Can't found " + path)
            if should_copy(path, os.path.join(binary_path, path)):
                shutil.copy(path, os.path.join(binary_path, path))
        return self.ssh.process(*args, setuid=setuid, **kwargs)

    def attach(self, target, gdbscript='', gdb_path='gdb'):
        if type(target) == int:
            pid: int = target
        else:
            assert type(target) == ssh_process
            target: ssh_process
            pid: int = target.pid

        gdbscript = 'target extended-remote {}\nattach {}\n{}'.format(
            os.path.join(binary_path, 'socket', '{}-gdbserver'.format(self.container_name)), pid, gdbscript)

        tmp = tempfile.NamedTemporaryFile(
            dir=self.tmp_dir.name, prefix='pwn', suffix='.gdb', delete=False, mode='w+')
        tmp.write(gdbscript)
        tmp.close()
        cmd = [gdb_path, '-q', '-x', tmp.name]
        misc.run_in_new_terminal(cmd)
