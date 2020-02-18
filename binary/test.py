from pwn import *
from docker_debug import *

context.terminal = ['tmux', 'splitw', '-h']

def main():
    debug_env = DockerDebug('ubuntu-1704')
    # program path in docker
    p = debug_env.process('./sh')
    debug_env.attach(p, gdbscript='')
    p.interactive()

if __name__ == '__main__':
    main()

