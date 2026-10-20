#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE   /* O_NOFOLLOW, pread/pwrite on older glibc */
#endif

#include "grandnullifier.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define BUF_SIZE   (1u << 20)
#define PASS_RAND  -1   /* a pattern byte, or random data */

/* ---- methods ------------------------------------------------------------ */

static const int g_standard[] = { PASS_RAND };
static const int g_enhanced[] = { 0x00, 0xFF, PASS_RAND };
static const int g_professional[] = { 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, PASS_RAND };

static const gn_method_info g_info[GN_METHOD_COUNT] = {
    { "Standard",     "standard",     "NIST SP 800-88 Clear",       1,  0 },
    { "Enhanced",     "enhanced",     "US Air Force AFSSI-5020",    3,  0 },
    { "Professional", "professional", "Canadian RCMP TSSIT OPS-II", 7,  1 },
    { "Ultimate",     "ultimate",     "Pfitzner",                   33, 0 },
};

static int
pass_pattern(gn_method m, int pass)
{
    switch (m) {
    case GN_STANDARD:     return g_standard[pass];
    case GN_ENHANCED:     return g_enhanced[pass];
    case GN_PROFESSIONAL: return g_professional[pass];
    default:              return PASS_RAND;   /* Pfitzner: random throughout */
    }
}

const gn_method_info *
gn_method_get(gn_method m)
{
    return (int)m >= 0 && m < GN_METHOD_COUNT ? &g_info[m] : NULL;
}

static int
same_ci(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
    return *a == *b;
}

int
gn_method_find(const char *name)
{
    int i;
    if (!name) return -1;
    for (i = 0; i < GN_METHOD_COUNT; i++)
        if (same_ci(name, g_info[i].key) || same_ci(name, g_info[i].alias)) return i;
    return -1;
}

const char *
gn_strerror(int rc)
{
    switch (rc) {
    case GN_OK:            return "wiped";
    case GN_ERR_ARG:       return "bad method or path";
    case GN_ERR_NOT_FILE:  return "not a regular file (directories, links and devices are skipped)";
    case GN_ERR_OPEN:      return "could not open the file for writing";
    case GN_ERR_WRITE:     return "could not write the file";
    case GN_ERR_VERIFY:    return "the last pass did not read back as written";
    case GN_ERR_REMOVE:    return "overwritten, but could not be deleted";
    case GN_ERR_CANCELLED: return "stopped; the file is partly overwritten";
    case GN_ERR_RANDOM:    return "no system random source";
    default:               return "failed";
    }
}

/* ---- random ------------------------------------------------------------- */

/* The system's random source seeds xoshiro256**, fast enough to fill the
 * disk's bandwidth. A seeded generator also lets the verify pass regenerate
 * exactly what the last random pass wrote. */
static int
os_random(void *buf, size_t n)
{
#if defined(_WIN32)
    return BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    unsigned char *p = (unsigned char *)buf;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    while (n) {
        ssize_t got = read(fd, p, n);
        if (got <= 0) {
            if (got < 0 && errno == EINTR) continue;
            close(fd);
            return 0;
        }
        p += got;
        n -= (size_t)got;
    }
    close(fd);
    return 1;
#endif
}

typedef struct rng { uint64_t s[4]; } rng;

static uint64_t
rotl(uint64_t x, int k)
{
    return (x << k) | (x >> (64 - k));
}

static uint64_t
rng_next(rng *r)
{
    uint64_t *s = r->s, out = rotl(s[1] * 5, 7) * 9, t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45);
    return out;
}

static void
rng_fill(rng *r, unsigned char *buf, size_t n)
{
    while (n >= 8) {
        uint64_t v = rng_next(r);
        memcpy(buf, &v, 8);
        buf += 8;
        n -= 8;
    }
    if (n) {
        uint64_t v = rng_next(r);
        memcpy(buf, &v, n);
    }
}

/* ---- files -------------------------------------------------------------- */

#if defined(_WIN32)
typedef HANDLE gn_fd;
#define GN_BAD_FD INVALID_HANDLE_VALUE

static wchar_t *
widen(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof *w);
    if (w && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) <= 0) {
        free(w);
        w = NULL;
    }
    return w;
}

static int
file_open(const char *path, gn_fd *fd, uint64_t *size)
{
    wchar_t *w = widen(path);
    DWORD attr;
    LARGE_INTEGER sz;

    if (!w) return GN_ERR_ARG;
    attr = GetFileAttributesW(w);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        free(w);
        return GN_ERR_OPEN;
    }
    if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) {
        free(w);
        return GN_ERR_NOT_FILE;
    }
    if (attr & FILE_ATTRIBUTE_READONLY) SetFileAttributesW(w, attr & ~FILE_ATTRIBUTE_READONLY);
    *fd = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                      FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(w);
    if (*fd == INVALID_HANDLE_VALUE) return GN_ERR_OPEN;
    if (!GetFileSizeEx(*fd, &sz)) {
        CloseHandle(*fd);
        return GN_ERR_OPEN;
    }
    *size = (uint64_t)sz.QuadPart;
    return GN_OK;
}

static int
file_seek0(gn_fd fd)
{
    LARGE_INTEGER z;
    z.QuadPart = 0;
    return SetFilePointerEx(fd, z, NULL, FILE_BEGIN) != 0;
}

static int
file_write(gn_fd fd, const void *buf, size_t n)
{
    DWORD wrote = 0;
    return WriteFile(fd, buf, (DWORD)n, &wrote, NULL) && wrote == n;
}

static int
file_read(gn_fd fd, void *buf, size_t n)
{
    DWORD got = 0;
    return ReadFile(fd, buf, (DWORD)n, &got, NULL) && got == n;
}

static int file_sync(gn_fd fd) { return FlushFileBuffers(fd) != 0; }

static int
file_truncate(gn_fd fd)
{
    return file_seek0(fd) && SetEndOfFile(fd) && FlushFileBuffers(fd);
}

static void file_close(gn_fd fd) { CloseHandle(fd); }

static int
file_rename(const char *from, const char *to)
{
    wchar_t *a = widen(from), *b = widen(to);
    int ok = a && b && MoveFileExW(a, b, MOVEFILE_WRITE_THROUGH);
    free(a);
    free(b);
    return ok;
}

static int
file_remove(const char *path)
{
    wchar_t *w = widen(path);
    int ok = w && DeleteFileW(w);
    free(w);
    return ok;
}

#else
typedef int gn_fd;
#define GN_BAD_FD -1

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

static int
file_open(const char *path, gn_fd *fd, uint64_t *size)
{
    struct stat st;

    if (lstat(path, &st) != 0) return GN_ERR_OPEN;
    if (!S_ISREG(st.st_mode)) return GN_ERR_NOT_FILE;
    *fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (*fd < 0) return GN_ERR_OPEN;
    /* The same file lstat saw, not one swapped in since. */
    if (fstat(*fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(*fd);
        return GN_ERR_NOT_FILE;
    }
    *size = (uint64_t)st.st_size;
    return GN_OK;
}

static int file_seek0(gn_fd fd) { return lseek(fd, 0, SEEK_SET) == 0; }

static int
file_write(gn_fd fd, const void *buf, size_t n)
{
    const unsigned char *p = (const unsigned char *)buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        p += w;
        n -= (size_t)w;
    }
    return 1;
}

static int
file_read(gn_fd fd, void *buf, size_t n)
{
    unsigned char *p = (unsigned char *)buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return 0;
        }
        p += r;
        n -= (size_t)r;
    }
    return 1;
}

static int
file_sync(gn_fd fd)
{
#if defined(__APPLE__) && defined(F_FULLFSYNC)
    /* fsync on macOS stops at the drive's cache. */
    if (fcntl(fd, F_FULLFSYNC) == 0) return 1;
#endif
    return fsync(fd) == 0;
}

static int file_truncate(gn_fd fd) { return ftruncate(fd, 0) == 0 && file_sync(fd); }
static void file_close(gn_fd fd) { close(fd); }
static int file_rename(const char *from, const char *to) { return rename(from, to) == 0; }
static int file_remove(const char *path) { return unlink(path) == 0; }
#endif

/* ---- wiping ------------------------------------------------------------- */

static void
fill(unsigned char *buf, size_t n, int pattern, rng *r)
{
    if (pattern == PASS_RAND) rng_fill(r, buf, n);
    else memset(buf, pattern, n);
}

static int
write_pass(gn_fd fd, unsigned char *buf, uint64_t size, int pattern, rng *r, int pass,
           int passes, gn_progress_fn progress, void *user)
{
    uint64_t done = 0;

    if (!file_seek0(fd)) return GN_ERR_WRITE;
    if (pattern != PASS_RAND) memset(buf, pattern, BUF_SIZE);
    while (done < size) {
        size_t n = size - done < BUF_SIZE ? (size_t)(size - done) : BUF_SIZE;
        if (pattern == PASS_RAND) rng_fill(r, buf, n);
        if (!file_write(fd, buf, n)) return GN_ERR_WRITE;
        done += n;
        if (progress && progress(user, pass, passes, done, size)) return GN_ERR_CANCELLED;
    }
    return file_sync(fd) ? GN_OK : GN_ERR_WRITE;
}

static int
verify_pass(gn_fd fd, unsigned char *buf, unsigned char *want, uint64_t size, int pattern,
            rng *r, int step, gn_progress_fn progress, void *user)
{
    uint64_t done = 0;

    if (!file_seek0(fd)) return GN_ERR_VERIFY;
    while (done < size) {
        size_t n = size - done < BUF_SIZE ? (size_t)(size - done) : BUF_SIZE;
        fill(want, n, pattern, r);
        if (!file_read(fd, buf, n) || memcmp(buf, want, n) != 0) return GN_ERR_VERIFY;
        done += n;
        if (progress && progress(user, step, step, done, size)) return GN_ERR_CANCELLED;
    }
    return GN_OK;
}

/* A random name of the same folder, so the old name is not left in the directory. */
static char *
random_name(const char *path, rng *r)
{
    static const char hex[] = "0123456789abcdef";
    const char *slash = strrchr(path, '/');
    size_t dir, i;
    char *out;

#if defined(_WIN32)
    const char *bs = strrchr(path, '\\');
    if (bs && (!slash || bs > slash)) slash = bs;
#endif
    dir = slash ? (size_t)(slash - path) + 1 : 0;
    out = (char *)malloc(dir + 17);
    if (!out) return NULL;
    memcpy(out, path, dir);
    for (i = 0; i < 16; i++) out[dir + i] = hex[rng_next(r) & 15];
    out[dir + 16] = '\0';
    return out;
}

int
gn_wipe_file(const char *path, gn_method m, unsigned flags, gn_progress_fn progress,
             void *user)
{
    const gn_method_info *info = gn_method_get(m);
    unsigned char *buf = NULL, *want = NULL;
    uint64_t size = 0;
    gn_fd fd = GN_BAD_FD;
    rng r, last;
    char *tmp;
    int rc, pass, steps;

    if (!info || !path || !*path) return GN_ERR_ARG;
    if (!os_random(r.s, sizeof r.s)) return GN_ERR_RANDOM;
    rc = file_open(path, &fd, &size);
    if (rc != GN_OK) return rc;

    buf = (unsigned char *)malloc(BUF_SIZE);
    want = info->verify ? (unsigned char *)malloc(BUF_SIZE) : NULL;
    if (!buf || (info->verify && !want)) {
        rc = GN_ERR_WRITE;
        goto done;
    }
    /* Progress counts the read-back as one more step after the passes. */
    steps = info->passes + (info->verify ? 1 : 0);
    last = r;
    for (pass = 0; pass < info->passes && rc == GN_OK; pass++) {
        int pattern = pass_pattern(m, pass);
        if (pass == info->passes - 1) last = r;   /* where the last pass's data starts */
        rc = write_pass(fd, buf, size, pattern, &r, pass + 1, steps, progress, user);
    }
    if (rc == GN_OK && info->verify)
        rc = verify_pass(fd, buf, want, size, pass_pattern(m, info->passes - 1), &last, steps,
                         progress, user);
    if (rc == GN_OK && !(flags & GN_KEEP) && !file_truncate(fd)) rc = GN_ERR_WRITE;

done:
    file_close(fd);
    free(buf);
    free(want);
    if (rc != GN_OK || (flags & GN_KEEP)) return rc;

    tmp = random_name(path, &r);
    if (tmp && file_rename(path, tmp)) {
        rc = file_remove(tmp) ? GN_OK : GN_ERR_REMOVE;
    } else {
        rc = file_remove(path) ? GN_OK : GN_ERR_REMOVE;
    }
    free(tmp);
    return rc;
}

/* ---- folders ------------------------------------------------------------ */

enum { KIND_MISSING, KIND_FILE, KIND_DIR, KIND_LINK, KIND_OTHER };

typedef struct walk {
    gn_method      m;
    unsigned       flags;
    gn_file_fn     on_file;
    gn_progress_fn progress;
    void          *user;
    int            rc, stop;
} walk;

static void
note(walk *w, const char *path, int rc)
{
    if (rc != GN_OK && w->rc == GN_OK) w->rc = rc;
    if (w->on_file) w->on_file(w->user, path, rc);
}

static void walk_path(walk *w, const char *path);

#if defined(_WIN32)
static char *
narrow(const wchar_t *s)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    char *out = n > 0 ? (char *)malloc((size_t)n) : NULL;
    if (out) WideCharToMultiByte(CP_UTF8, 0, s, -1, out, n, NULL, NULL);
    return out;
}

static int
path_kind(const char *path)
{
    wchar_t *w = widen(path);
    DWORD a = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    free(w);
    if (a == INVALID_FILE_ATTRIBUTES) return KIND_MISSING;
    if (a & FILE_ATTRIBUTE_REPARSE_POINT) return KIND_LINK;
    if (a & FILE_ATTRIBUTE_DIRECTORY) return KIND_DIR;
    if (a & FILE_ATTRIBUTE_DEVICE) return KIND_OTHER;
    return KIND_FILE;
}

/* A link or junction itself, not what it points to. */
static int
remove_link(const char *path)
{
    wchar_t *w = widen(path);
    DWORD a = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    int ok = w && ((a & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(w) : DeleteFileW(w));
    free(w);
    return ok;
}

static int
remove_dir(const char *path)
{
    wchar_t *w = widen(path);
    int ok = w && RemoveDirectoryW(w);
    free(w);
    return ok;
}

static void
walk_dir(walk *w, const char *path)
{
    size_t n = strlen(path);
    char *pattern = (char *)malloc(n + 3);
    wchar_t *wp;
    WIN32_FIND_DATAW fd;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (pattern) {
        memcpy(pattern, path, n);
        memcpy(pattern + n, "\\*", 3);
        wp = widen(pattern);
        if (wp) h = FindFirstFileW(wp, &fd);
        free(wp);
        free(pattern);
    }
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char *name, *child;
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        name = narrow(fd.cFileName);
        child = name ? (char *)malloc(n + strlen(name) + 2) : NULL;
        if (child) {
            memcpy(child, path, n);
            child[n] = '\\';
            memcpy(child + n + 1, name, strlen(name) + 1);
            walk_path(w, child);
        }
        free(child);
        free(name);
    } while (!w->stop && FindNextFileW(h, &fd));
    FindClose(h);
}
#else
#include <dirent.h>

static int
path_kind(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0) return KIND_MISSING;
    if (S_ISLNK(st.st_mode)) return KIND_LINK;
    if (S_ISDIR(st.st_mode)) return KIND_DIR;
    if (S_ISREG(st.st_mode)) return KIND_FILE;
    return KIND_OTHER;
}

static int remove_link(const char *path) { return unlink(path) == 0; }
static int remove_dir(const char *path) { return rmdir(path) == 0; }

static void
walk_dir(walk *w, const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    size_t n = strlen(path);

    if (!d) return;
    while (!w->stop && (e = readdir(d)) != NULL) {
        size_t len;
        char *child;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        len = strlen(e->d_name);
        child = (char *)malloc(n + len + 2);
        if (!child) continue;
        memcpy(child, path, n);
        child[n] = '/';
        memcpy(child + n + 1, e->d_name, len + 1);
        walk_path(w, child);
        free(child);
    }
    closedir(d);
}
#endif

static void
walk_path(walk *w, const char *path)
{
    int kind = path_kind(path), rc;

    if (w->stop) return;
    switch (kind) {
    case KIND_FILE:
        if (w->on_file && w->on_file(w->user, path, GN_STARTING)) {
            w->stop = 1;
            if (w->rc == GN_OK) w->rc = GN_ERR_CANCELLED;
            return;
        }
        rc = gn_wipe_file(path, w->m, w->flags & GN_KEEP, w->progress, w->user);
        if (rc == GN_ERR_CANCELLED) w->stop = 1;
        note(w, path, rc);
        return;
    case KIND_DIR:
        if (!(w->flags & GN_RECURSIVE)) {
            note(w, path, GN_ERR_NOT_FILE);
            return;
        }
        walk_dir(w, path);
        if (!w->stop && !(w->flags & GN_KEEP))
            note(w, path, remove_dir(path) ? GN_OK : GN_ERR_REMOVE);
        return;
    case KIND_LINK:
        /* Inside a folder being wiped the link goes; named directly, it is refused. */
        if (w->flags & GN_RECURSIVE && !(w->flags & GN_KEEP))
            note(w, path, remove_link(path) ? GN_OK : GN_ERR_REMOVE);
        else
            note(w, path, GN_ERR_NOT_FILE);
        return;
    case KIND_MISSING:
        note(w, path, GN_ERR_OPEN);
        return;
    default:
        note(w, path, GN_ERR_NOT_FILE);
        return;
    }
}

int
gn_wipe_path(const char *path, gn_method m, unsigned flags, gn_file_fn on_file,
             gn_progress_fn progress, void *user)
{
    walk w;

    if (!gn_method_get(m) || !path || !*path) return GN_ERR_ARG;
    memset(&w, 0, sizeof w);
    w.m = m;
    w.flags = flags;
    w.on_file = on_file;
    w.progress = progress;
    w.user = user;
    w.rc = GN_OK;
    walk_path(&w, path);
    return w.rc;
}

/* ---- progress and time left --------------------------------------------- */

typedef struct measure {
    unsigned  flags;
    uint64_t *files, *bytes;
} measure;

static void measure_path(measure *ms, const char *path);

#if defined(_WIN32)
static uint64_t
file_size_of(const char *path)
{
    wchar_t *w = widen(path);
    WIN32_FILE_ATTRIBUTE_DATA d;
    uint64_t n = 0;
    if (w && GetFileAttributesExW(w, GetFileExInfoStandard, &d))
        n = ((uint64_t)d.nFileSizeHigh << 32) | d.nFileSizeLow;
    free(w);
    return n;
}

static void
measure_dir(measure *ms, const char *path)
{
    size_t n = strlen(path);
    char *pattern = (char *)malloc(n + 3);
    wchar_t *wp;
    WIN32_FIND_DATAW fd;
    HANDLE h = INVALID_HANDLE_VALUE;

    if (pattern) {
        memcpy(pattern, path, n);
        memcpy(pattern + n, "\\*", 3);
        wp = widen(pattern);
        if (wp) h = FindFirstFileW(wp, &fd);
        free(wp);
        free(pattern);
    }
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        char *name, *child;
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        name = narrow(fd.cFileName);
        child = name ? (char *)malloc(n + strlen(name) + 2) : NULL;
        if (child) {
            memcpy(child, path, n);
            child[n] = '\\';
            memcpy(child + n + 1, name, strlen(name) + 1);
            measure_path(ms, child);
        }
        free(child);
        free(name);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static double
now_seconds(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER t;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
}
#else
#include <time.h>

static uint64_t
file_size_of(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0 ? (uint64_t)st.st_size : 0;
}

static void
measure_dir(measure *ms, const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    size_t n = strlen(path);

    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        size_t len;
        char *child;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        len = strlen(e->d_name);
        child = (char *)malloc(n + len + 2);
        if (!child) continue;
        memcpy(child, path, n);
        child[n] = '/';
        memcpy(child + n + 1, e->d_name, len + 1);
        measure_path(ms, child);
        free(child);
    }
    closedir(d);
}

static double
now_seconds(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
#endif

static void
measure_path(measure *ms, const char *path)
{
    switch (path_kind(path)) {
    case KIND_FILE:
        (*ms->files)++;
        *ms->bytes += file_size_of(path);
        break;
    case KIND_DIR:
        if (ms->flags & GN_RECURSIVE) measure_dir(ms, path);
        break;
    default:
        break;
    }
}

void
gn_measure(const char *path, unsigned flags, uint64_t *files, uint64_t *bytes)
{
    measure ms;
    if (!path || !files || !bytes) return;
    ms.flags = flags;
    ms.files = files;
    ms.bytes = bytes;
    measure_path(&ms, path);
}

void
gn_meter_begin(gn_meter *mt, gn_method m, uint64_t bytes)
{
    const gn_method_info *info = gn_method_get(m);
    memset(mt, 0, sizeof *mt);
    mt->total = bytes * (uint64_t)(info ? info->passes + (info->verify ? 1 : 0) : 1);
    mt->started = mt->rate_at = now_seconds();
}

void
gn_meter_progress(gn_meter *mt, int pass, int passes, uint64_t done, uint64_t total)
{
    double t = now_seconds();

    mt->file_size = total;
    mt->file_passes = passes;
    mt->current = mt->base + (uint64_t)(pass - 1) * total + done;
    /* A rate over the last half second or more, smoothed, so the estimate
     * neither jumps with each buffer nor clings to a slow start. */
    if (t - mt->rate_at >= 0.5) {
        double r = (double)(mt->current - mt->rate_bytes) / (t - mt->rate_at);
        mt->rate = mt->rate > 0.0 ? mt->rate * 0.7 + r * 0.3 : r;
        mt->rate_at = t;
        mt->rate_bytes = mt->current;
    }
}

void
gn_meter_file_done(gn_meter *mt)
{
    mt->base += mt->file_size * (uint64_t)mt->file_passes;
    mt->current = mt->base;
    mt->file_size = 0;
    mt->file_passes = 0;
}

double
gn_meter_fraction(const gn_meter *mt)
{
    if (!mt->total) return 1.0;
    return mt->current >= mt->total ? 1.0 : (double)mt->current / (double)mt->total;
}

double
gn_meter_elapsed(const gn_meter *mt)
{
    return now_seconds() - mt->started;
}

double
gn_meter_eta(const gn_meter *mt)
{
    double rate = mt->rate;
    if (gn_meter_elapsed(mt) < 1.0 || mt->current == 0) return -1.0;
    if (rate <= 0.0) rate = (double)mt->current / gn_meter_elapsed(mt);
    if (rate <= 0.0) return -1.0;
    return (double)(mt->total > mt->current ? mt->total - mt->current : 0) / rate;
}

void
gn_format_duration(double s, char *out, size_t cap)
{
    long t;
    if (s < 0.0) {
        snprintf(out, cap, "--");
        return;
    }
    t = (long)(s + 0.5);
    if (t >= 3600) snprintf(out, cap, "%ld h %02ld min", t / 3600, (t / 60) % 60);
    else if (t >= 60) snprintf(out, cap, "%ld min %02ld s", t / 60, t % 60);
    else snprintf(out, cap, "%ld s", t);
}
