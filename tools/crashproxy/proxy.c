// dsh 崩溃钩子 proxy —— 用作 APK 里的 libmain.so
// 作用：
//   1) 安装 SIGSEGV/SIGABRT/... 处理器，崩溃时把信号、backtrace、maps 写盘
//   2) dlopen libhachimi.so 并把 JNI_OnLoad 转过去（Hachimi 自己会再加载 libmain_orig.so）
//
// 日志落盘位置（按顺序尝试，第一个写成功就用它）：
//   /sdcard/Android/media/<包名>/dsh_crash.log   ← 别的应用可读
//   /sdcard/Download/dsh_crash.log               ← 若应用有 legacy 存储权限
//   /data/local/tmp/dsh_crash.log

#include <jni.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <execinfo.h>

static char g_logpath[256];
static int g_fd = -1;

static void resolve_path(void) {
    char pkg[128] = {0};
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) {
        size_t n = fread(pkg, 1, sizeof(pkg) - 1, f);
        (void)n;
        fclose(f);
    }
    for (char *p = pkg; *p; p++) if (*p == ':') { *p = 0; break; }
    const char *cands[] = {
        "/sdcard/Download/dsh_crash.log",
        "/data/local/tmp/dsh_crash.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        int fd = open(cands[i], O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd >= 0) { g_fd = fd; snprintf(g_logpath, sizeof(g_logpath), "%s", cands[i]); return; }
    }
    if (pkg[0]) {
        char buf[256];
        snprintf(buf, sizeof(buf), "/sdcard/Android/media/%s", pkg);
        mkdir(buf, 0777);
        snprintf(buf, sizeof(buf), "/sdcard/Android/media/%s/dsh_crash.log", pkg);
        int fd = open(buf, O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd >= 0) { g_fd = fd; snprintf(g_logpath, sizeof(g_logpath), "%s", buf); }
    }
}

static void wlog(const char *s) {
    if (g_fd < 0) resolve_path();
    if (g_fd >= 0) { write(g_fd, s, strlen(s)); fsync(g_fd); }
}

static void wfmt(const char *fmt, ...) {
    char b[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    wlog(b);
}

static void on_signal(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    wfmt("\n=== SIGNAL %d (%s) addr=%p pid=%d\n", sig, strsignal(sig), si ? si->si_addr : NULL, getpid());
    void *bt[64];
    int n = backtrace(bt, 64);
    for (int i = 0; i < n; i++) wfmt("  #%d %p\n", i, bt[i]);
    wlog("--- /proc/self/maps ---\n");
    FILE *f = fopen("/proc/self/maps", "r");
    if (f) { char line[512]; while (fgets(line, sizeof(line), f)) wlog(line); fclose(f); }
    wlog("--- end ---\n");
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((constructor)) static void init(void) {
    resolve_path();
    wfmt("=== dsh proxy loaded, log=%s\n", g_logpath);
    static char altstack[256 * 1024];
    stack_t ss = { .ss_sp = altstack, .ss_size = sizeof(altstack), .ss_flags = 0 };
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_signal;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    int sigs[] = { SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTRAP };
    for (unsigned i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) sigaction(sigs[i], &sa, NULL);
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    wlog("=== JNI_OnLoad enter\n");
    void *h = dlopen("libhachimi.so", RTLD_NOW | RTLD_GLOBAL);
    if (!h) wfmt("dlopen libhachimi.so FAILED: %s\n", dlerror());
    else {
        wlog("libhachimi.so loaded\n");
        jint (*fn)(JavaVM *, void *) = (jint (*)(JavaVM *, void *))dlsym(h, "JNI_OnLoad");
        if (fn) {
            wlog("calling hachimi JNI_OnLoad\n");
            jint r = fn(vm, reserved);
            wfmt("hachimi JNI_OnLoad returned %d\n", (int)r);
            return r;
        }
        wlog("libhachimi.so 没有 JNI_OnLoad\n");
    }
    wlog("fallback: 直接加载 libmain_orig.so\n");
    void *o = dlopen("libmain_orig.so", RTLD_NOW | RTLD_GLOBAL);
    if (o) {
        jint (*g)(JavaVM *, void *) = (jint (*)(JavaVM *, void *))dlsym(o, "JNI_OnLoad");
        if (g) return g(vm, reserved);
    }
    return JNI_ERR;
}