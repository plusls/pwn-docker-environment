from pwn import *
from docker_debug import *

#context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['wt.exe', '-w', '0', 'split-pane', 'wsl.exe', '-e']
# context.log_level = 'debug'
def main():
    debug_env = DockerDebug('ubuntu-1604')
    # program path in docker
    p = debug_env.process('./sh')
    debug_env.attach(p, gdbscript='')
    p.interactive()

if __name__ == '__main__':
    main()

