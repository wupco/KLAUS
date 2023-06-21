import sys
from pygdbmi.gdbcontroller import GdbController
import subprocess
from pwn import *

p = None

def open_gdbtub(target):
    gdbmi = GdbController()
    gdbmi.write("file "+target)
    return gdbmi

def get_response(gdbmi, func):
    response = gdbmi.write("disas "+func, timeout_sec=20)
    disas = list()
    for r in response:
        if r['stream'] == 'stdout' and r['payload']:
            payload = r['payload']
            if "0xffff" in payload:
                disas.append(payload.strip())
    return disas

def addr2line(addr):
    global p
    p.sendline(addr)
    aa = p.readline()
    assert(b"0xffff" in aa)
    bb = p.readline().decode().strip()
    return bb

def init_process(target):
    global p
    cmd = "addr2line -a -e " + target
    p = process(cmd.split(' '))

# def addr2line(addr, target):
#     cmd = "addr2line -ie " + target + " " + addr
#     process = subprocess.Popen(cmd.split(" "), stdout=subprocess.PIPE,
#                 stderr=subprocess.PIPE, stdin=subprocess.PIPE)
#     res = process.stdout.read().strip()
#     return res

def test():
    vmlinux = sys.argv[1]
    gdb = open_gdbtub(vmlinux)
    source_list = [b"/home/zip/kernel_bugs/cases/3619dec5_oob_diff_sys/e2efc2d134365d870c4d67a8351e1f7e88f0805b/1/linux/kernel/bpf/syscall.c:1334"]
    dis = get_response(gdb, "bpf_prog_load")
    init_process(vmlinux)
    current_cov = None
    import ipdb; ipdb.set_trace()
    for line in dis:
        addr, inst = line.split('\\t')
        addr = addr.split(" ")[0].strip()
        # addr = int(addr, 0x10)
        if "cov_trace_pc" in inst:
            print(line)
            current_cov = addr
        else:
            res = addr2line(addr)
            # print(res)
            if res in source_list:
                import ipdb; ipdb.set_trace()
                print(current_cov)
                print("Found")
                raw_input()

def parse_file(source_file):
    location = {}
    with open(source_file, 'rb') as f:
        for line in f.readlines():
            func, source = line.decode().strip().split(", ")
            source = source.replace("linux-bitcode", "linux") # replace the dir
            if func in location.keys():
                location[func].add(source)
            else:
                location[func] = {source}
    return location

def similar_location(addr, addrs):
    path, line = addr.split(":")
    if path not in "".join(addrs):
        return False

    for addr_ in addrs:
        _, line_ = addr_.split(":")
        if line_ == "?": continue
        if line == "?": continue
        if abs(int(line) - int(line_)) <= 10:
            return True
    return False

def main():
    vmlinux = sys.argv[1]
    source_file = sys.argv[2]
    target_file = sys.argv[3]
    gdb = open_gdbtub(vmlinux)
    init_process(vmlinux)
    location = parse_file(source_file)

    # print(location)

    addresses = set()
    for key in location.keys():
        dis = get_response(gdb, key)
        current_cov = None
        found = False
        for line in dis:
            addr, inst = line.split("\\t")
            addr = addr.split(" ")[0].strip()

            if "cov_trace_pc" in inst:
                current_cov = addr
            else:
                res = addr2line(addr)
                # clear res
                res = res.split(" ")[0].strip()
                if res in location[key]:
                    if current_cov is None:
                        continue
                    addr = int(current_cov, 0x10) & 0xffffffff
                    # size of inst `call __sanitizer_cov_trace_pc`
                    addresses.add(addr+5)
                    found = True
        
        if found: continue

        for line in dis:
            addr, inst = line.split("\\t")
            addr = addr.split(" ")[0].strip()

            if "cov_trace_pc" in inst:
                current_cov = addr
            else:
                res = addr2line(addr)
                res = res.split(" ")[0].strip()
                if similar_location(res, location[key]):
                    if current_cov is None:
                        continue
                    addr = int(current_cov, 0x10) & 0xffffffff
                    # size of inst `call __sanitizer_cov_trace_pc`
                    addresses.add(addr+5)
                    found = True

        if not found:
            for line in dis:
                addr, inst = line.split("\\t")
                addr = addr.split(" ")[0].strip()

                if "cov_trace_pc" in inst:
                    addr = int(current_cov, 0x10) & 0xffffffff
                    addresses.add(addr+5)
                    found = True
                    break
        if not found:
            print("didn't found "+key)
        
    
    # pack
    data = p32(len(addresses))
    for addr in addresses:
        data += p32(addr)
    assert (len(addresses) != 0)
    
    with open(target_file, 'wb') as f:
        f.write(data)

    print("Writed %d to %s"%(len(addresses), sys.argv[3]))
    p.close()

if __name__ == "__main__":
    main()