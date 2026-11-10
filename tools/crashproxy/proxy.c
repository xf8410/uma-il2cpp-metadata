// dsh 崩溃钩子 proxy —— 用作 APK 里的 libmain.so
// 作用：
//   1) 启动前写好 Hachimi 配置（强制开文件日志 enable_file_logging / debug_mode）
//   2) 安装 SIGSEGV/SIGABRT/... 处理器，崩溃时写信号 + backtrace + maps
//   3) dlopen libhachimi.so 并把 JNI_OnLoad 转过去
//
// 落盘位置：
//   /sdcard/Download/dsh_crash.log                         ← DSH 直接可读
//   /sdcard/Android/media/<包名>/hachimi/config.json        ← Hachimi 配置（官方路径）
//   /sdcard/Android/media/<包名>/hachimi/hachimi.log        ← Hachimi 自己的日志

#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/types.h>

extern int backtrace(void **buffer, int size);

static char g_logpath[256];
static int g_fd = -1;
static char g_pkg[128];

static void read_pkg(void) {
    if (g_pkg[0]) return;
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) {
        size_t n = fread(g_pkg, 1, sizeof(g_pkg) - 1, f);
        (void)n;
        fclose(f);
    }
    for (char *p = g_pkg; *p; p++) if (*p == ':') { *p = 0; break; }
}

static void resolve_path(void) {
    read_pkg();
    const char *cands[] = {
        "/sdcard/Download/dsh_crash.log",
        "/data/local/tmp/dsh_crash.log",
        NULL
    };
    for (int i = 0; cands[i]; i++) {
        int fd = open(cands[i], O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd >= 0) { g_fd = fd; snprintf(g_logpath, sizeof(g_logpath), "%s", cands[i]); return; }
    }
    if (g_pkg[0]) {
        char buf[256];
        snprintf(buf, sizeof(buf), "/sdcard/Android/media/%s", g_pkg);
        mkdir(buf, 0777);
        snprintf(buf, sizeof(buf), "/sdcard/Android/media/%s/dsh_crash.log", g_pkg);
        int fd = open(buf, O_CREAT | O_WRONLY | O_APPEND, 0666);
        if (fd >= 0) { g_fd = fd; snprintf(g_logpath, sizeof(g_logpath), "%s", buf); }
    }
}

static void wlog(const char *s) {
    if (g_fd < 0) resolve_path();
    if (g_fd >= 0) { ssize_t w = write(g_fd, s, strlen(s)); (void)w; fsync(g_fd); }
}

static void wfmt(const char *fmt, ...) {
    char b[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof(b), fmt, ap); va_end(ap);
    wlog(b);
}

static void mkdirs(const char *path) {
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0777); *p = '/'; }
    }
    mkdir(tmp, 0777);
}

// 把 Hachimi 配置改成「开日志、跳过首次设置」，这样它启动过程就会写 hachimi.log
static void seed_hachimi_config(void) {
    read_pkg();
    if (!g_pkg[0]) { wlog("seed config: 拿不到包名\n"); return; }
    char dir[256], cfg[300], logf[300];
    snprintf(dir, sizeof(dir), "/sdcard/Android/media/%s/hachimi", g_pkg);
    mkdirs(dir);
    snprintf(cfg, sizeof(cfg), "%s/config.json", dir);
    snprintf(logf, sizeof(logf), "%s/hachimi.log", dir);

    struct stat st;
    if (stat(cfg, &st) == 0) wfmt("seed config: 已存在 (%ld B)，覆盖\n", (long)st.st_size);
    else wlog("seed config: 不存在，创建\n");

    const char *json =
        "{\n"
        "  \"enable_file_logging\": true,\n"
        "  \"debug_mode\": true,\n"
        "  \"skip_first_time_setup\": true\n"
        "}\n";
    int fd = open(cfg, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (fd >= 0) {
        ssize_t w = write(fd, json, strlen(json));
        (void)w;
        close(fd);
        wfmt("seed config: 写入成功 -> %s\n", cfg);
    } else {
        wfmt("seed config: 写入失败 -> %s (errno=%d)\n", cfg, errno);
    }
    wfmt("hachimi 日志应为: %s\n", logf);
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
    wfmt("\n=== dsh proxy loaded, log=%s pkg=%s\n", g_logpath, g_pkg);
    static char altstack[256 * 1024];
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = 0;
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
    seed_hachimi_config();
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