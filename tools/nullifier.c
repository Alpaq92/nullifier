/* nullifier: the Grand Nullifier console tool.
 *
 * On a terminal it keeps a live panel at the bottom, redrawn in place with
 * ANSI escape codes (Windows 10 and later, Linux, macOS, the BSDs; no curses).
 * Piped or with --plain it prints one line per file instead. */
#include "grandnullifier.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <io.h>
#include <shellapi.h>
#define isatty _isatty
#define fileno _fileno
#else
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#endif

#define PANEL_LINES 5

static struct {
    int method, recursive, yes, quiet, plain;
    int live;                 /* the panel is on */
    int color;
    int wiped, failed;
    uint64_t files_total, file_index;
    int pass, passes;
    uint64_t file_done, file_size;
    gn_meter meter;
    double last_draw;
    int drawn;                /* lines of panel on screen */
    const char *current;
    volatile sig_atomic_t stop;
} O = { GN_STANDARD };

/* ---- terminal ----------------------------------------------------------- */

static double
now(void)
{
#if defined(_WIN32)
    return (double)GetTickCount64() / 1000.0;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
#endif
}

static int
term_width(void)
{
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO i;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &i))
        return i.srWindow.Right - i.srWindow.Left + 1;
#else
    struct winsize w;
    if (ioctl(fileno(stderr), TIOCGWINSZ, &w) == 0 && w.ws_col > 0) return w.ws_col;
#endif
    return 80;
}

/* ANSI on the Windows console has to be asked for. */
static int
term_init(void)
{
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode;
    if (!GetConsoleMode(h, &mode)) return 0;
    return SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
#else
    const char *t = getenv("TERM");
    return !t || strcmp(t, "dumb") != 0;
#endif
}

static const char *
c(const char *code)
{
    return O.color ? code : "";
}

#define DIM   "\x1b[2m"
#define BOLD  "\x1b[1m"
#define RED   "\x1b[31m"
#define GREEN "\x1b[32m"
#define CYAN  "\x1b[36m"
#define RESET "\x1b[0m"

static void
panel_clear(void)
{
    if (!O.drawn) return;
    fprintf(stderr, "\x1b[%dA", O.drawn);
    for (int i = 0; i < O.drawn; i++) fputs("\x1b[2K\n", stderr);
    fprintf(stderr, "\x1b[%dA", O.drawn);
    O.drawn = 0;
}

/* A bar of `width` cells in Unicode eighths. */
static void
bar(char *out, size_t cap, double f, int width)
{
    static const char *const part[8] = { "", "\xe2\x96\x8f", "\xe2\x96\x8e", "\xe2\x96\x8d",
                                         "\xe2\x96\x8c", "\xe2\x96\x8b", "\xe2\x96\x8a",
                                         "\xe2\x96\x89" };
    int eighths = (int)(f * width * 8.0 + 0.5), i, n = 0;
    size_t at = 0;

    if (eighths > width * 8) eighths = width * 8;
    out[0] = 0;
    for (i = 0; i < eighths / 8 && at + 4 < cap; i++, n++)
        at += (size_t)snprintf(out + at, cap - at, "\xe2\x96\x88");
    if (eighths % 8 && at + 4 < cap) {
        at += (size_t)snprintf(out + at, cap - at, "%s", part[eighths % 8]);
        n++;
    }
    for (; n < width && at + 4 < cap; n++)
        at += (size_t)snprintf(out + at, cap - at, "\xe2\x96\x91");
}

static void
format_bytes(uint64_t n, char *out, size_t cap)
{
    static const char *const unit[] = { "B", "KB", "MB", "GB", "TB" };
    double v = (double)n;
    int u = 0;
    while (v >= 1024.0 && u < 4) {
        v /= 1024.0;
        u++;
    }
    snprintf(out, cap, u ? "%.1f %s" : "%.0f %s", v, unit[u]);
}

/* The last `room` characters of a path, from a character boundary. */
static const char *
fit_tail(const char *s, int room)
{
    size_t n = strlen(s);
    if (room < 4 || (int)n <= room) return s;
    s += n - (size_t)room + 3;
    while (((unsigned char)*s & 0xC0) == 0x80) s++;
    return s;
}

static void
panel_draw(int force)
{
    const gn_method_info *m = gn_method_get((gn_method)O.method);
    char b1[256], b2[256], done[24], total[24], left[32], took[32], speed[24];
    int w = term_width(), bw;
    double t = now(), eta;

    if (!force && t - O.last_draw < 0.1) return;
    O.last_draw = t;
    bw = w - 34;
    if (bw > 40) bw = 40;
    if (bw < 10) bw = 10;

    panel_clear();
    fprintf(stderr, "%sGrand Nullifier%s \xc2\xb7 %s \xe2\x80\x94 %d pass%s%s (%s)\n",
            c(BOLD), c(RESET), m->alias, m->passes, m->passes == 1 ? "" : "es",
            m->verify ? " + verify" : "", m->standard);
    fprintf(stderr, "File   %llu of %llu   %s%s%s\n", (unsigned long long)O.file_index,
            (unsigned long long)O.files_total, c(CYAN),
            O.current ? fit_tail(O.current, w - 24) : "", c(RESET));
    bar(b1, sizeof b1, O.file_size ? (double)O.file_done / (double)O.file_size : 0.0, bw);
    if (m->verify && O.pass > m->passes)
        fprintf(stderr, "Verify           %s %3d%%\n", b1,
                O.file_size ? (int)(O.file_done * 100 / O.file_size) : 0);
    else
        fprintf(stderr, "Pass   %d of %-3d  %s %3d%%\n", O.pass, m->passes, b1,
                O.file_size ? (int)(O.file_done * 100 / O.file_size) : 0);
    format_bytes(O.meter.current, done, sizeof done);
    format_bytes(O.meter.total, total, sizeof total);
    bar(b2, sizeof b2, gn_meter_fraction(&O.meter), bw);
    fprintf(stderr, "Total           %s%s%s %3d%%  %s of %s\n", c(GREEN), b2, c(RESET),
            (int)(gn_meter_fraction(&O.meter) * 100.0), done, total);
    eta = gn_meter_eta(&O.meter);
    gn_format_duration(eta, left, sizeof left);
    gn_format_duration(gn_meter_elapsed(&O.meter), took, sizeof took);
    format_bytes((uint64_t)(O.meter.rate > 0.0 ? O.meter.rate : 0.0), speed, sizeof speed);
    fprintf(stderr, "%s%s/s  \xc2\xb7  %s elapsed  \xc2\xb7  %s%s%s\n", c(DIM), speed, took,
            eta >= 0.0 ? "about " : "", eta >= 0.0 ? left : "estimating the time left",
            eta >= 0.0 ? " left" : "");
    fputs(c(RESET), stderr);
    fflush(stderr);
    O.drawn = PANEL_LINES;
}

/* A message that should stay: printed above the panel, which follows it. */
static void
say(FILE *f, const char *color, const char *path, const char *what)
{
    panel_clear();
    fprintf(f, "%s%s%s: %s\n", c(color), path, c(RESET), what);
    fflush(f);
    if (O.live) panel_draw(1);
}

/* ---- callbacks ---------------------------------------------------------- */

static int
progress(void *user, int pass, int passes, uint64_t done, uint64_t total)
{
    (void)user;
    O.pass = pass;
    O.passes = passes;
    O.file_done = done;
    O.file_size = total;
    gn_meter_progress(&O.meter, pass, passes, done, total);
    if (O.live) panel_draw(0);
    return O.stop;
}

static int
on_file(void *user, const char *path, int rc)
{
    int is_file;
    (void)user;
    if (rc == GN_STARTING) {
        O.current = path;
        O.file_index++;
        O.pass = 0;
        O.file_done = O.file_size = 0;
        if (O.live) panel_draw(1);
        return O.stop;
    }
    is_file = O.current && !strcmp(O.current, path);
    O.current = NULL;
    gn_meter_file_done(&O.meter);
    if (rc == GN_OK) {
        if (is_file) O.wiped++;
        if (O.plain && !O.quiet) printf("%s: wiped\n", path);
    } else if (rc == GN_ERR_CANCELLED) {
        say(stderr, DIM, path, "stopped; partly overwritten");
    } else {
        O.failed++;
        say(stderr, RED, path,
            rc == GN_ERR_NOT_FILE && !O.recursive ? "not a file (add -r for a folder)"
                                                  : gn_strerror(rc));
    }
    return 0;
}

#if defined(_WIN32)
static BOOL WINAPI
on_break(DWORD type)
{
    (void)type;
    O.stop = 1;
    return TRUE;
}
#else
static void
on_signal(int sig)
{
    (void)sig;
    O.stop = 1;
}
#endif

/* ---- main --------------------------------------------------------------- */

static void
usage(FILE *f)
{
    int i;
    fprintf(f,
            "nullifier %s (Grand Nullifier) - overwrite files, then delete them\n"
            "\n"
            "Usage: nullifier [-m METHOD] [-r] [-y] [--plain|-q] PATH...\n"
            "\n"
            "  -m, --method METHOD  how to overwrite (default: standard)\n"
            "  -r, --recursive      wipe folders and everything in them\n"
            "  -y, --yes            do not ask before wiping\n"
            "      --plain          a line per file instead of the live panel\n"
            "  -q, --quiet          only errors\n"
            "  -l, --list           list the methods\n"
            "  -h, --help\n"
            "\nCtrl+C stops after the current buffer; that file is left partly\n"
            "overwritten, the rest untouched.\n"
            "\nMethods:\n", GN_VERSION);
    for (i = 0; i < GN_METHOD_COUNT; i++) {
        const gn_method_info *m = gn_method_get((gn_method)i);
        fprintf(f, "  %-13s %2d pass%s%s  (%s)\n", m->key, m->passes,
                m->passes == 1 ? "  " : "es", m->verify ? " + verify" : "         ", m->standard);
    }
    fprintf(f,
            "\nOn SSDs, copy-on-write or snapshotting file systems (APFS, Btrfs, ZFS,\n"
            "Windows shadow copies) and synced folders, old copies of the data can\n"
            "survive whatever the method; use full-disk encryption there.\n");
}

static int
confirm(int n)
{
    char line[16];
    const gn_method_info *m = gn_method_get((gn_method)O.method);

    fprintf(stderr, "Wipe %d path%s with %s (%d pass%s)? This cannot be undone. [y/N] ",
            n, n == 1 ? "" : "s", m->alias, m->passes, m->passes == 1 ? "" : "es");
    if (!fgets(line, sizeof line, stdin)) return 0;
    return line[0] == 'y' || line[0] == 'Y';
}

static int
run(int argc, char **argv)
{
    uint64_t bytes = 0;
    int i, first, n;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
        if (a[0] != '-' || !a[1]) break;
        if (!strcmp(a, "-h") || !strcmp(a, "--help") || !strcmp(a, "-l") ||
            !strcmp(a, "--list")) {
            usage(stdout);
            return 0;
        }
        if (!strcmp(a, "-r") || !strcmp(a, "--recursive")) O.recursive = 1;
        else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) O.yes = 1;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) O.quiet = 1;
        else if (!strcmp(a, "--plain")) O.plain = 1;
        else if ((!strcmp(a, "-m") || !strcmp(a, "--method")) && i + 1 < argc) {
            O.method = gn_method_find(argv[++i]);
            if (O.method < 0) {
                fprintf(stderr, "nullifier: unknown method '%s' (see: nullifier --list)\n",
                        argv[i]);
                return 2;
            }
        } else {
            fprintf(stderr, "nullifier: unknown option '%s' (see: nullifier --help)\n", a);
            return 2;
        }
    }
    first = i;
    n = argc - first;
    if (n <= 0) {
        usage(stderr);
        return 2;
    }
    if (!O.yes && !confirm(n)) {
        fprintf(stderr, "nullifier: nothing wiped\n");
        return 1;
    }

    O.live = !O.quiet && !O.plain && isatty(fileno(stderr)) && term_init();
    O.color = O.live && !getenv("NO_COLOR");
    if (!O.live) O.plain = !O.quiet;
#if defined(_WIN32)
    SetConsoleCtrlHandler(on_break, TRUE);
#else
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#endif

    for (i = first; i < argc; i++)
        gn_measure(argv[i], O.recursive ? GN_RECURSIVE : 0, &O.files_total, &bytes);
    gn_meter_begin(&O.meter, (gn_method)O.method, bytes);
    if (O.live) fputs("\x1b[?25l", stderr);   /* hide the cursor while drawing */

    for (i = first; i < argc && !O.stop; i++)
        gn_wipe_path(argv[i], (gn_method)O.method, O.recursive ? GN_RECURSIVE : 0, on_file,
                     progress, NULL);

    if (O.live) {
        panel_clear();
        fputs("\x1b[?25h", stderr);
    }
    if (!O.quiet && (O.wiped + O.failed > 1 || O.stop)) {
        char took[32];
        gn_format_duration(gn_meter_elapsed(&O.meter), took, sizeof took);
        printf("%s%d wiped, %d failed in %s%s\n", O.stop ? "stopped: " : "", O.wiped,
               O.failed, took, O.stop ? "; the rest are untouched" : "");
    } else if (!O.quiet && O.live && O.wiped == 1) {
        printf("1 file wiped\n");
    }
    return O.failed || O.stop ? 1 : 0;
}

#if defined(_WIN32)
static char *
narrow(const wchar_t *w)
{
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char *)malloc((size_t)(n > 0 ? n : 1));
    if (s) {
        s[0] = '\0';
        WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    }
    return s;
}

/* UTF-8 arguments, whatever the console's code page. */
int
main(void)
{
    int argc, i, rc;
    wchar_t **wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    char **argv = wargv ? (char **)calloc((size_t)argc + 1, sizeof *argv) : NULL;
    UINT cp = GetConsoleOutputCP();

    if (!argv) return 2;
    for (i = 0; i < argc; i++) argv[i] = narrow(wargv[i]);
    SetConsoleOutputCP(CP_UTF8);
    rc = run(argc, argv);
    SetConsoleOutputCP(cp);
    for (i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    LocalFree(wargv);
    return rc;
}
#else
int
main(int argc, char **argv)
{
    return run(argc, argv);
}
#endif
