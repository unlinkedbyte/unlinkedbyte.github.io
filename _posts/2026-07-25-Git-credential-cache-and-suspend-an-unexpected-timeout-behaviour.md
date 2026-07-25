---
layout: post
title: "Git credential-cache and suspend: an unexpected timeout behavior"
date: 2026-07-26
categories: [research]
tags: [git, research]
---

Many times in this life, we look for answers. But those answers, objectively, are usually subjective. 

That is why we must ask ourselves: are we asking the right questions? How do I know if it is the right question?

Despite the initial drama, it applies to this post.

The real question about what I am going to propose is not whether there is a vulnerability or not. **The real question is, if there is one, what is the magnitude of its impact?** (although maybe the right question is whether I should upload this post or not haha!).

### How we got here
Yesterday I spent the whole afternoon writing and researching for the post that I ended up uploading late last night. 

When I finally had a decent research done and the post looked good (in my opinion) I decided to upload it using the terminal as I usually do. 

**Where does the problem arise?** After doing it, due to all the accumulated exhaustion, I simply put the computer into suspension mode. When I woke up, I was rereading the post to see how it turned out, looking for any possible typos, and there was one in the "final thoughts"--I had forgotten to add a hashtag (###, it was a title). I simply changed it and did the typical git push origin main. Here is where my surprise came: despite having the timeout configured to 3600 (before the checks), it was uploaded without having to enter credentials, even though 8 hours had passed! So obviously, this unexpected behaviour got my attention.

### The proof
To start with, we had to rule out a "false positive" by running the relevant checks; these are the commands I used after configuring a new timeout of 240 seconds:

1. **Identify the PID:**

```bash
$pgrep -af 'git-credential-cache--daemon|credential-cache'

The output: 

132194 /usr/lib/git-core/git credential-cache--daemon /home/ygm/.cache/git/credential/socket
```

2. **Active time:**
```bash
ps -o etimes=,pid=,cmd= -p 132194

The output: 

77  132194 /usr/lib/git-core/git credential-cache--daemon /home/ygm/.cache/git/credential/socket
```

I did not use it again for the simple reason you will se below, as strace already indicates the execution time, but using it after many hours, where there should be thousands of seconds, should show you that barely any time has passed.

3. **The trace**
```bash
sudo strace -tt -p 132194

The output:

strace: Process 132194 attached
12:56:25.098425 restart_syscall(<... resuming interrupted poll ...>) = ? ERESTART_RESTARTBLOCK (Interrupted by signal)
13:06:24.580587 restart_syscall(<... resuming interrupted poll ...>) = 1
13:06:37.276303 accept(3, NULL, NULL)   = 1
13:06:37.276506 dup(1)                  = 5
13:06:37.276853 fcntl(1, F_GETFL)       = 0x2 (flags O_RDWR)
13:06:37.277110 fcntl(5, F_GETFL)       = 0x2 (flags O_RDWR)
13:06:37.277313 fstat(1, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0
13:06:37.277553 read(1, "action=get\ntimeout=240\ncapabilit"..., 4096) = 126
13:06:37.277658 read(1, "", 4096)       = 0
13:06:37.277727 fstat(5, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0
13:06:37.277816 close(1)                = 0
13:06:37.277920 write(5, "capability[]=authtype\nusername=u"..., 94) = 94
13:06:37.278037 close(5)                = 0
13:06:37.278155 poll([{fd=3, events=POLLIN}], 1, 30000) = 1 ([{fd=3, revents=POLLIN}])
13:06:37.579367 accept(3, NULL, NULL)   = 1
13:06:37.579639 dup(1)                  = 5
13:06:37.579787 fcntl(1, F_GETFL)       = 0x2 (flags O_RDWR)
13:06:37.579891 fcntl(5, F_GETFL)       = 0x2 (flags O_RDWR)
13:06:37.579929 fstat(1, {st_mode=S_IFSOCK|0777, st_size=0, ...}) = 0
13:06:37.579975 read(1, "action=store\ntimeout=240\ncapabil"..., 4096) = 150
13:06:37.580033 read(1, "", 4096)       = 0
13:06:37.580071 close(1)                = 0
13:06:37.580109 close(5)                = 0
13:06:37.580154 poll([{fd=3, events=POLLIN}], 1, 240000) = 0 (Timeout)
13:10:37.678410 poll([{fd=3, events=POLLIN}], 1, 30000) = 0 (Timeout)
13:11:07.697365 close(3)                = 0
13:11:07.697662 unlink("/home/ygm/.cache/git/credential/socket") = 0
13:11:07.698340 fstat(-1, 0x7ffc8ed06c70) = -1 EBADF (Descriptor de fichero erróneo)
13:11:07.699037 getpid()                = 132194
13:11:07.699359 exit_group(0)           = ?
13:11:07.700012 +++ exited with 0 +++
```

4. **The checker and the time we use for checking**
```
git config --global --list

The output:
user.email= -----------
user.name=unlinkedbyte
credential.helper=cache --timeout=240
                                  '-'
                        |___________|          
```

If you look at the first lines of the strace output, you can see that we have a time difference of 15 minutes even though we have 240 seconds configured.

Why this has happened? What could the impact be? Could a password leak through a RAM dump or some other kind of leakage if someone escalate privileges on our machine and, because we were unaware of this unexpected behaviour, the credentials are still in memory? 


### The investigation
The investigation has focused more on how the flow of time is supposed to stop, which clock it uses, why the credential had not expired yet, and wheter the developers may have already taken this into account, and, since it may not have a serious impact, they may have left as is. Perhaps it is more like a logic flaw instead of a security issue. Perhaps.

*Before anything else, I should mention that this investigation was carried out with substantial help from a powerful LLM (after weighing the possible impact of the issue) so that I could keep spending time on assembly and binary analysis.*


To find out exactly why this happens, we first turned to Git's source code, specifically `credential-cache--daemon.c`. The daemon stores credentials in an in-memory array, assigning each entry a timestamp: `expiration = time(NULL) + timeout`. However, there is only one place in the entire code that purges expired entries: the `check_expirations()` function. 

This function is called at a very specific point within the main loop:

```c
static int serve_cache_loop(int fd) {
    wakeup = check_expirations();     // 1. Cleans expired entries, calculates remaining time
    ...
    poll(&pfd, 1, 1000 * wakeup);     // 2. Waits for those seconds... or a new connection
    if (pfd.revents & POLLIN) {
        ...
        serve_one_client(in, out);    // 3. If a client connects, services it IMMEDIATELY
    }
}
```

This means `check_expirations()` only re-executes if `poll()` fully exhausts its timeout. If a new connection arrives instead (like our `git push` right after waking up the laptop), `poll()` returns immediately due to the event, bypassing the timeout countdown. The code jumps straight to `serve_one_client()`, which for a `get` action calls `lookup_credential()`. Crucially, `lookup_credential()` **does not check** the expiration timestamp at all; it merely checks if the entry still exists in the array.

#### The Suspension Twist: The Linux Kernel's Clock Logic

The real plot twist is why `poll()` didn't trigger its timeout after 8 hours of real-world time. `poll()` measures its wait time using the kernel's monotonic clock. In Linux, by design, `CLOCK_MONOTONIC` pauses and does not count the time the system spends in suspension. For that, `CLOCK_BOOTTIME` exists, which does keep counting during sleep.

This is not a minor accidental detail. There was an attempt in the past to unify these clocks inside the kernel, but it was specifically reverted because `systemd` and other daemons heavily rely on the behavior of `CLOCK_MONOTONIC`. After the revert, it was observed that daemons would suffer unexpected timeouts and related issues upon waking up from a suspend state. Therefore, Git's credential daemon falls exactly into this category of processes whose timeouts become "elastic" around a system suspension due to kernel architecture, not a local bug in Git.

To prove this beyond doubt, we went straight to the another source: the Linux kernel code itself. In `fs/select.c`, the actual implementation of the `poll()` syscall reveals the missing piece:

```c
SYSCALL_DEFINE3(poll, struct pollfd __user *, ufds, unsigned int, nfds, int, timeout_msecs)
{
    ...
    poll_select_set_timeout(to, timeout_msecs / MSEC_PER_SEC, ...);
    ...
}

int poll_select_set_timeout(struct timespec64 *to, time64_t sec, long nsec)
{
    ...
    ktime_get_ts64(to);   // <- This fixes the starting point of the timeout
    *to = timespec64_add_safe(*to, ts);
}
```

`ktime_get_ts64()` is specifically the accessor for the monotonic clock family inside the kernel. (There is `ktime_get_real_ts64()` for wall time and `ktime_get_boottime_ts64()` for boottime). Since `poll()` relies on the monotonic clock and not the boottime one, we can draw a direct line between Git's `poll(&pfd, 1, 1000 * wakeup)` and a clock that stops ticking when the lid is closed.

#### Context & Real Impact

Interestingly, there is a recent issue in `git-lfs` where users reported that the credential cache timer seemed to reset with each use (commit/pull), causing credentials to persist longer than configured. Although that involves a different mechanism (re-use overwriting the timer instead of system suspension), it stems from the same underlying symptom: the credential cache timeout is less rigid than the documentation suggests. It seems this elasticity was well within the trade-offs considered by the developers.

Ultimately, the real impact is tightly contained. The Unix socket remains strictly restricted to your local user via filesystem permissions, meaning there is no remote exposure or data leak. The only thing this edge case breaks is the "defense in depth" assumption that setting a timeout guarantees a immutable window of exposure in real-world time. It is, in the end, just a fascinating edge case at the intersection of software logic and power management.

