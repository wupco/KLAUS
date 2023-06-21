import sys
import os

ANALYZER_PATH="./build/lib/analyzer"

def find_changes():
    patch = ""
    if len(sys.argv) < 2:
        print(sys.argv[0] + " patch.diff")
        exit(-1)
    else:
        patch = open(sys.argv[1]).read()
    assert(patch != "")

    changed = {}
    cur_file = ""

    for line in patch.split("\n"):
        if line.startswith("--- a/"):
            f = line[6::]
            cur_file = f
            # if f not in changed_file:
            #     changed_file.append(f)
            #     print("Found changed file "+line[6::])
        if line.startswith("@@ "):
            func = line.split("@@")[-1]
            if "(" not in func:
                continue
            func = func.split("(")[0].split(" ")[-1]
            func = func.replace("*", "")
            assert(cur_file != "")

            if cur_file not in changed:
                changed[cur_file] = set()
                changed[cur_file].add(func)
            else:
                changed[cur_file].add(func)
            print("Found changed func "+func+" in "+cur_file)
    return changed

def run_analyzer(changed):
    root_dir = os.path.dirname(sys.argv[1])
    root_dir = os.path.realpath(root_dir)
    os.system("rm /tmp/cond.txt /tmp/prop.txt")
    for f in changed:
        if f.endswith(".h"): continue
        for func in changed[f]:        
            cmd = ANALYZER_PATH
            cmd += " --patched-bc="+root_dir+"/linux_buggy_patched/"+f+".bc"
            cmd += " --raw-bc="+root_dir+"/linux_bug/"+f+".bc"
            cmd += " --func="+func
            cmd += " "+root_dir+"/linux_bug/"+f+".bc"
            print("cmd: "+cmd)
            res = os.system(cmd)
            if res != 0:
                print("res not 0: "+str(res))
                print("cmd: "+cmd)
                cmd += " --disable-llvm-diff=1"
                os.system(cmd)
    if "--dry-run" not in sys.argv[-1]:
        os.system("mv /tmp/cond.txt /tmp/prop.txt "+root_dir)

def main():
    changed = find_changes()
    run_analyzer(changed)

if __name__ == "__main__":
    main()
