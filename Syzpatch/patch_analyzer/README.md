# find bad variable

`sudo apt install libstdc++-10-dev` to solve issue that shows cannot find lstdc++

1. get execution trace.
patch poc.c: when starting new thread, insert a call to enable kcov. reset a call to disable kcov(make sure we have encough space for storing insts after exiting)
patch the kernel on kcov_task_exit in kernel/kcov.c
```c
if (!strcmp(t->comm, "poc")) {
    return;
}
```
this is because some crashes happen when calling exit. we keep track of pc for poc after exiting.

on gdb side:
set a breakpoint on do_exit. if t->comm is `poc`, collect the track information.
when crash happens, find the pid of crash and get the track info of corresponding task.

2. locate the crashing ip.
we will skip kasan related api.
find the line of code crashed
