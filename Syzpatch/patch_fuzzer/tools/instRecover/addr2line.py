from pwn import *
import sys

#context.log_level = 'debug'
vmlinux = sys.argv[1]
cov_file = sys.argv[2]

cmd = "addr2line -a -f -e "+vmlinux
p = process(cmd.split(' '))

covs = []
with open(cov_file) as f:
    covs = f.read().split("\n")

lines = []

for c in covs:
    c = c.strip()
    if c == '': continue

    p.sendline(c)
    p.readline()
    func = p.readline().strip()
    line = p.readline().strip()
    print(func + b":" + line)
    lines.append((func,line))
