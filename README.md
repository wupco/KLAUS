# KLAUS

A framework to test the correctness of the Linux kernel patch.

### Docker-env
Docker environment for KLAUS.

KLAUS requires two arguments:
+ commitid: The commit id of the buggy patch.
+ syzid: The bug report id of the bug that the patch fixes.

e.g. To test the correctness of the patch `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=730c5fd42c1e`, we need the commitid `730c5fd42c1e` and the bug report(`https://syzkaller.appspot.com/bug?id=53b6555b27af2cae74e2fbdac6cadc73f9cb18aa`) id `53b6555b27af2cae74e2fbdac6cadc73f9cb18aa` that this patch fixes.

```bash
cd Docker-env
docker build -t klaus . 
docker run -v $(pwd)/data:/data --rm -it --privileged klaus
# static analysis and instrumentation.
cd /data/fuzz_cfgs_dir/
python3 build_env.py [commitid] [syzid]
# start fuzzing.
cd [commitid]
./fuzz_start.sh
```

### Syzpatch
Source code of KLAUS.
+ patch_analyzer: static analysis tool.
+ patch_fuzzer: fuzzing instance.
+ setup_env: script to build the enviroment for cases.
+ syzPatch-gcc: the tool to instrument feedback for fuzzer.
