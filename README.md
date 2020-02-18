# pwn-docker-environment

Debug pwn in docker, no need for virtual machines



## Introduction

Did you debug pwn in a virtual machine?

Are you still worried about the virtual machine taking up too much hard disk?

![1.png](readme/1.png)

Try this!

Just need to install the basic libraries in docker, you can debug the program as usual!

The docker image will take up very little space.

![2.png](readme/2.png)



## Quick Start

1. Install docker and docker-compose pwndbg

2. Add your user to docker group.

3. Install requirements:

   ```bash
   pip3 install docker pwntools asyncssh --user
   ```

4. Install pwn-docker-environment.

   ```bash
   git clone https://github.com/plusls/pwn-docker-environment.git
   cd pwn-docker-environment
   docker-compose up -d
   ```

5. Run test script:

   test.py use tmux as terminal, you can change it to your terminal。

   ```bash
   cd binary
   python3 test.py
   ```
   ![3.png](readme/3.png)



