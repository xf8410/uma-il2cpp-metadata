// dsh 崩溃钩子 proxy —— 用作 APK 里的 libmain.so
// 1) 在多个候选路径写 Hachimi 配置（强制开日志）
// 2) 看门狗线程：每 0.5s 记一次存活，并把 Hachimi 自己的日志「抄」到可读位置
// 3) 信号处理器：SIGSEGV/ABRT/... 时写 backtrace + maps
// 4) dlopen libhachimi.so 并转发 JNI_OnLoad
//
// 日志落盘：/sdcard/Android/media/<包名>/dsh_crash.log（DSH 可读）
//           /sdcard/Download/dsh_crash.log（首次可写时优先）

#define _GNU_SOURCE
#include <jni.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/stat.h>
#include <sys/types.h>

extern int backtrace(void **buffer, int size);

static char g_logpath[256];
static int g_fd = -1;
static char g_pkg[128];
static char g_halog[256];   // Hachimi 可能的日志路径（第一个存在的）

static void read_pkg(void) {
    if (g_pkg[0]) return;
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (f) { size_t n = fread(g_pkg, 1, sizeof(g_pkg) - 1, f); (void)n; fclose(f); }
    for (char *p = g_pkg; *p; p++) if (*p == ':') { *p = 0; break; }
}

static void resolve_path(void) {
    read_pkg();
    const char *cands[] = { "/sdcard/Download/dsh_crash.log", "/data/local/tmp/dsh_crash.log", NULL };
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
    for (char *p = tmp + 1; *p; p++) if (*p == '/') { *p = 0; mkdir(tmp, 0777); *p = '/'; }
    mkdir(tmp, 0777);
}

static const char *CONFIG_JSON =
    "{\n"
    "  \"enable_file_logging\": true,\n"
    "  \"debug_mode\": true,\n"
    "  \"skip_first_time_setup\": true\n"
    "}\n";

// Hachimi(v0.14.0) 可能读这些位置，全部写一遍；并记录各自是否成功
static void seed_hachimi_config(void) {
    read_pkg();
    if (!g_pkg[0]) { wlog("seed: 拿不到包名\n"); return; }
    const char *tmpl[] = {
        "/sdcard/Android/data/%s/files/hachimi",
        "/sdcard/Android/media/%s/hachimi",
        "/data/data/%s/files/hachimi",
        "/data/user/0/%s/files/hachimi",
        NULL
    };
    for (int i = 0; tmpl[i]; i++) {
        char dir[256], cfg[300];
        snprintf(dir, sizeof(dir), tmpl[i], g_pkg);
        mkdirs(dir);
        snprintf(cfg, sizeof(cfg), "%s/config.json", dir);
        int fd = open(cfg, O_CREAT | O_WRONLY | O_TRUNC, 0666);
        if (fd >= 0) {
            ssize_t w = write(fd, CONFIG_JSON, strlen(CONFIG_JSON));
            (void)w; close(fd);
            wfmt("seed: OK   %s\n", cfg);
        } else {
            wfmt("seed: FAIL %s (errno=%d)\n", cfg, errno);
        }
        char lg[300];
        snprintf(lg, sizeof(lg), "%s/hachimi.log", dir);
        if (!g_halog[0] && access(lg, R_OK) == 0) snprintf(g_halog, sizeof(g_halog), "%s", lg);
    }
    if (!g_halog[0]) {
        snprintf(g_halog, sizeof(g_halog), "/sdcard/Android/data/%s/files/hachimi/hachimi.log", g_pkg);
    }
    wfmt("seed: 预期 hachimi 日志 = %s\n", g_halog);
}

// 把 Hachimi 日志的尾部抄进我们自己的日志（因为它的目录 DSH 读不到）
static void copy_halog_tail(void) {
    if (!g_halog[0]) return;
    int fd = open(g_halog, O_RDONLY);
    if (fd < 0) return;
    off_t sz = lseek(fd, 0, SEEK_END);
    off_t start = sz > 8192 ? sz - 8192 : 0;
    lseek(fd, start, SEEK_SET);
    char buf[8193];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    wfmt("---- hachimi.log tail (%lld B, from %lld) ----\n", (long long)n, (long long)start);
    wlog(buf);
    wlog("\n---- end tail ----\n");
}

static void *watchdog(void *arg) {
    (void)arg;
    int tick = 0;
    for (;;) {
        usleep(500 * 1000);
        tick++;
        if (tick % 4 == 0) wfmt("alive %.1fs\n", tick * 0.5);
        if (tick == 2 || tick % 6 == 0) copy_halog_tail();
    }
    return NULL;
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
    copy_halog_tail();
    wlog("--- end ---\n");
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((constructor)) static void init(void) {
    resolve_path();
    wfmt("\n=== dsh proxy loaded log=%s pkg=%s\n", g_logpath, g_pkg);
    static char altstack[256 * 1024];
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack; ss.ss_size = sizeof(altstack); ss.ss_flags = 0;
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
    pthread_t th;
    if (pthread_create(&th, NULL, watchdog, NULL) == 0) wlog("watchdog started\n");
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
    wlog("fallback: 加载 libmain_orig.so\n");
    void *o = dlopen("libmain_orig.so", RTLD_NOW | RTLD_GLOBAL);
    if (o) {
        jint (*g)(JavaVM *, void *) = (jint (*)(JavaVM *, void *))dlsym(o, "JNI_OnLoad");
        if (g) return g(vm, reserved);
    }
    return JNI_ERR;
}