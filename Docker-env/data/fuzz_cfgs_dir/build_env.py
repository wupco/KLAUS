#!/usr/bin/env python3
import os
import sys
import requests
import random

# configs
storage_dir = "/data/kernels/"
bitcode_clang_dir = "/llvm-project-10.0.1/build/bin/clang"
analyze_command = "python3 /patch_analyzer/analyze_patch.py"
work_base_dir = "/data/fuzz_workdir/"
special_gcc = "/gcc-bin/bin/gcc"
fuzzer_dir = "/klaus_fuzzer"
fuzzer_bin = fuzzer_dir + "/bin/syz-manager"
fuzzer_db  = fuzzer_dir + "/bin/syz-db"
fuzzer_cfgs_dir = "/data/fuzz_cfgs_dir/"


def create_project(caseid):
    os.system("mkdir -p {}{}".format(storage_dir,caseid))
    proj_dir = "{}{}".format(storage_dir,caseid)
    os.system("mkdir -p {}/linux_bug ".format(proj_dir))
    return proj_dir

def crawl_information(syzid):
    syzinfo = requests.get("https://syzkaller.appspot.com/bug?id=" + syzid).text
    patchlink = syzinfo.split('<span class="mono">')[1].split('<a href="')[1].split('"')[0]
    syzpoc = "https://syzkaller.appspot.com/" + syzinfo.split('<td class="repro">')[3].split('<a href="')[1].split('"')[0].replace("&amp;" , "&")
    config = "https://syzkaller.appspot.com/" + syzinfo.split('<td class="config">')[1].split('<a href="')[1].split('"')[0].replace("&amp;" , "&")
    commit_url = "https://git.kernel.org" + requests.get(patchlink).text.split("th>commit</th><td colspan='2' class='sha1'><a href='")[1].split("'>")[0]
    print(commit_url, syzpoc, config, patchlink)
    return commit_url, syzpoc, config, patchlink
def write_cfg(syzid, syzid_list, patchid, caseid, proj_dir):
    cfg_temp = '''#!/bin/sh
kernel_ver="{}"
syz_id_1="{}"
# other syzid1
{}
buggy_patch="{}"
syz_id_2="{}"
complete_patch="{}"
'''
    if syzid_list != [] :
        syzid_list_str = "\n".join(["#syz_id" + "=\"" + syzid_list[i] + "\"" for i in range(len(syzid_list))])
    else:
        syzid_list_str = ""
    config = cfg_temp.format("unk", syzid, syzid_list_str, patchid, "unk",  "unk")
    with open( proj_dir + "/" + caseid + ".cfg", "w") as f:
        f.write(config)
    
def write_env_files(config, proj_dir, patchlink):
    with open(proj_dir + "/config", "w") as f:
        f.write(requests.get(config).text)
    patchlink = patchlink.replace("commit","patch")
    patch = requests.get(patchlink).text
    with open(proj_dir + "/buggy.patch", "w") as f:
        f.write(patch)

def prepare_kernels(commit_url, proj_dir, commit_id):
    os.system("mkdir -p {}/linux_bug/".format(proj_dir))
    os.system("cd {}/linux_bug && git init && git remote add origin {}".format(proj_dir, commit_url))
    os.system("cd {}/linux_bug && git fetch origin {}".format(proj_dir, commitid))
    os.system("cd {}/linux_bug && git reset --hard FETCH_HEAD".format(proj_dir))
    os.system("cd {}/linux_bug && patch -p1 < {}/classmap.patch".format(proj_dir,fuzzer_cfgs_dir))
    os.system("cd {}/linux_bug && patch -R -p1 < {}/clang.patch".format(proj_dir,fuzzer_cfgs_dir))
    os.system("cp -r {}/linux_bug {}/linux_buggy_patched".format(proj_dir, proj_dir))
    os.system("cp -r {}/linux_bug {}/linux_buggy_patched_for_fuzz".format(proj_dir, proj_dir))
    os.system("cd {}/linux_bug && patch -R -p1 < ../buggy.patch".format(proj_dir))
    os.system("cp {}/config {}/linux_bug/.config".format(proj_dir, proj_dir))
    os.system("cp {}/config {}/linux_buggy_patched/.config".format(proj_dir, proj_dir))
    os.system("cd {}/linux_bug && ./scripts/config -d CONFIG_KASAN -d CONFIG_KCOV -d CONFIG_UBSAN -d CONFIG_KTSAN".format(proj_dir))
    os.system("cd {}/linux_buggy_patched && ./scripts/config -d CONFIG_KASAN -d CONFIG_KCOV -d CONFIG_UBSAN -d CONFIG_KTSAN".format(proj_dir))


def compile_bitcodes(proj_dir):
    os.system("cd {}/linux_bug && make clean".format(proj_dir))
    os.system("cd {}/linux_bug && yes \"\" | make CC={} -j`nproc`".format(proj_dir, bitcode_clang_dir))
    os.system("cd {}/linux_buggy_patched && make clean".format(proj_dir))
    os.system("cd {}/linux_buggy_patched && yes \"\" | make CC={} -j`nproc`".format(proj_dir, bitcode_clang_dir))

def analyze_patch(proj_dir):
     os.system("timeout 6h {} {}/buggy.patch".format(analyze_command, proj_dir))

def compile_fuzzing_kernel(proj_dir):
    os.system("cd {}/linux_buggy_patched_for_fuzz && make clean".format(proj_dir))
    os.system("cp {}/config {}/linux_buggy_patched_for_fuzz/.config".format(proj_dir, proj_dir))
    os.system("patch {}/linux_buggy_patched_for_fuzz/kernel/kcov.c ./kernel.patch".format(proj_dir))
    os.system("cd {}/linux_buggy_patched_for_fuzz && yes \"\" | COND_FILE={}/cond.txt PROP_FILE={}/prop.txt make CC={} -j`nproc`".format(proj_dir, proj_dir, proj_dir, special_gcc))
    
def build_fuzzing_env(caseid, syzpoc):
    os.system("mkdir -p ./{}".format(caseid))
    os.system("mkdir -p {}workdir_{}".format(work_base_dir, caseid))
    os.system("mkdir -p ./{}/db".format(caseid))
    config_temp = open("config").read()
    config = config_temp.replace("[id]", caseid)
    random_number = random.randint(10000, 60000)
    config = config.replace("[port]", str(random_number))
    with open("./{}/config".format(caseid), "w") as f:
        f.write(config)
    with open("./{}/poc".format(caseid), "w") as f:
        f.write(requests.get(syzpoc).text)
    os.system("cp ./{}/poc ./{}/db; ".format(caseid, caseid))
    os.system("{} pack ./{}/db ./{}/corpus.db".format(fuzzer_db, caseid, caseid))
    fuzz_start = """#/bin/bash
timeout 3d {} -config {}{}/config -auxiliary ../../../../..{}{}/poc 2>&1
""".format(fuzzer_bin, fuzzer_cfgs_dir, caseid, fuzzer_cfgs_dir, caseid)

    with open("./{}/fuzz_start.sh".format(caseid), "w") as f:
        f.write(fuzz_start)
    os.system("chmod +x ./{}/fuzz_start.sh".format(caseid))

def check_inst(caseid):
    function_list = ["__sanitizer_cov_enable_trace", "__sanitizer_cov_trace_int8", "__sanitizer_obj_cov_trace_pc", "__sanitizer_cov_pre_trace", "__sanitizer_cov_post_trace"]
    casepath = storage_dir + caseid + "/linux_buggy_patched_for_fuzz/"
    os.system("objdump -d {}/vmlinux > {}/vmlinux.objdump".format(casepath, casepath))
    with open("{}/vmlinux.objdump".format(casepath)) as f:
        for line in f:
            for func in function_list:
                if line.find(func) != -1 and (line.find("call") != -1 or line.find("jne") != -1):
                    print("{} has inst".format(caseid))
                    return 1
    return 0
# input
if len(sys.argv) != 3:
    print("Usage: python3 build_env.py [commitid] [syzid]")
    exit(0)
    
commitid = sys.argv[1] # The commit id of the buggy patch
syzid = sys.argv[2] # The bug report id of the bug that the patch fixed
# create a new project

# crawl information
commit_url, syzpoc, config, patchlink = crawl_information(syzid)
commitid = commit_url.split("?id=")[1]
commit_url = commit_url.split(".git")[0]
commit_url = commit_url.replace("git.kernel.org","kernel.googlesource.com")
proj_dir = create_project(commitid)
write_env_files(config, proj_dir, patchlink)
prepare_kernels(commit_url, proj_dir, commitid)
compile_bitcodes(proj_dir)
analyze_patch(proj_dir)
compile_fuzzing_kernel(proj_dir)
build_fuzzing_env(commitid, syzpoc)
if check_inst(commitid) != 1:
    print("{} failed".format(commitid))
    exit(0)
    
