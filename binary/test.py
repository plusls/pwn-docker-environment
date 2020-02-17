from pwn import *
from docker_debug import *

context.terminal = ['tmux', 'splitw', '-h']

def main():
    set_os('ubuntu-1704')
    # program path in docker
    p = process('./sh')
    # exe=path in host
    attach(p, gdbscript='')
    p.interactive()

if __name__ == '__main__':
    main()

