# ctf-easypwn-template

主要是为了做一些模板<br>
方便比赛的时候能直接用<br>
还有做题的时候方便<br>
不用就是每次遇到ret2libc
都要重新把那一大堆重复的代码写一遍

-t 指定目标 local 或者是 远程地址
    local的话就是直接打当前文件夹下的 pwn 文件<br>
-p 如果指定的是远程地址，就需要指定-p端口号<br>
-b 目标架构是32位还是64位

上面三个是两个文件中共有的内容
<h3>ret2text中特有的几个参数<h3><br>
-m  模式<br>
分为:
backdoor    存在后门函数
nowrite     存在 /bin/sh 和 system
write       存在system，需要自己写入/bin/sh字符串




