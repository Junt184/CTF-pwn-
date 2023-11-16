# -*- coding: utf-8 -*-
# @Time     : 2023/11/14 11:12
# @Author   : 君叹
# @File     : 命令行参数解析器.py


# -t <target>
# 判断 target 是不是local 不是 local 就当地址处理
# -p <port>
# -l <libc> # 指定了一套代码，没指定走另一套
# -b <32|64>


import argparse

parser = argparse.ArgumentParser(description="Process some integers")
parser.add_argument('-t', type=str, help='本地 or 远程地址')
parser.add_argument('-p', type=int, help='端口号')
parser.add_argument('-b', type=str, help='bit位')
parser.add_argument('-l', type=str, help='需要指定的libc地址')

args = parser.parse_args()
print(args)
print(1234)