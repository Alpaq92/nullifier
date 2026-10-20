/* Grand Nullifier's tests: every method on files of awkward sizes, and folders. */
#include "grandnullifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <direct.h>
#define make_dir(p) _mkdir(p)
#else
#include <sys/stat.h>
#define make_dir(p) mkdir(p, 0700)
#endif

static int g_files;

static int
on_file(void *user, const char *path, int rc)
{
    (void)user;
    (void)path;
    if (rc == GN_OK) g_files++;
    return 0;
}

static int g_checks, g_failures;

#define CHECK(c) do { g_checks++; if (!(c)) { g_failures++; \
    fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void
write_file(const char *path, size_t size)
{
    FILE *f = fopen(path, "wb");
    size_t i;
    if (!f) return;
    for (i = 0; i < size; i++) fputc('A' + (int)(i % 26), f);
    fclose(f);
}

static int
exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) fclose(f);
    return f != NULL;
}

/* 1 when the file kept its size and no longer holds the original text. */
static int
overwritten(const char *path, size_t size)
{
    FILE *f = fopen(path, "rb");
    size_t i, same = 0, n = 0;
    int c;
    if (!f) return 0;
    for (i = 0; (c = fgetc(f)) != EOF; i++, n++)
        if (c == 'A' + (int)(i % 26)) same++;
    fclose(f);
    return n == size && same < size / 10 + 1;
}

static int g_calls, g_stop_after;

static int
count(void *user, int pass, int passes, uint64_t done, uint64_t total)
{
    (void)user; (void)pass; (void)passes; (void)done; (void)total;
    return g_stop_after && ++g_calls >= g_stop_after;
}

int
main(void)
{
    static const size_t sizes[] = { 0, 1, 4095, 4096, 1048577, 3 * 1048576 + 7 };
    const char *path = "grandnullifier-test.bin";
    int m;
    size_t s;

    CHECK(gn_method_find("ultimate") == GN_ULTIMATE);
    CHECK(gn_method_find("Professional") == GN_PROFESSIONAL);
    CHECK(gn_method_find("gutmann") == -1);
    CHECK(gn_method_get(GN_STANDARD)->passes == 1);
    CHECK(gn_method_get(GN_ENHANCED)->passes == 3);
    CHECK(gn_method_get(GN_PROFESSIONAL)->passes == 7 && gn_method_get(GN_PROFESSIONAL)->verify);
    CHECK(gn_method_get(GN_ULTIMATE)->passes == 33);
    CHECK(gn_method_get(GN_METHOD_COUNT) == NULL);

    for (m = 0; m < GN_METHOD_COUNT; m++) {
        for (s = 0; s < sizeof sizes / sizeof sizes[0]; s++) {
            if (m == GN_ULTIMATE && sizes[s] > 4096) continue;   /* 33 passes: keep it quick */
            write_file(path, sizes[s]);
            CHECK(gn_wipe_file(path, (gn_method)m, GN_KEEP, NULL, NULL) == GN_OK);
            CHECK(overwritten(path, sizes[s]));
            CHECK(gn_wipe_file(path, (gn_method)m, 0, NULL, NULL) == GN_OK);
            CHECK(!exists(path));
        }
    }

    /* Stopping leaves the file where it was. */
    write_file(path, 3 * 1048576);
    g_stop_after = 2;
    CHECK(gn_wipe_file(path, GN_ENHANCED, 0, count, NULL) == GN_ERR_CANCELLED);
    CHECK(exists(path));
    g_stop_after = 0;
    CHECK(gn_wipe_file(path, GN_STANDARD, 0, count, NULL) == GN_OK);

    CHECK(gn_wipe_file("no-such-file.bin", GN_STANDARD, 0, NULL, NULL) == GN_ERR_OPEN);
    CHECK(gn_wipe_file(".", GN_STANDARD, 0, NULL, NULL) == GN_ERR_NOT_FILE);
    CHECK(gn_wipe_file(path, (gn_method)99, 0, NULL, NULL) == GN_ERR_ARG);

    /* Measuring and the meter. */
    {
        uint64_t files = 0, bytes = 0;
        gn_meter mt;
        char d[32];
        write_file(path, 5000);
        gn_measure(path, 0, &files, &bytes);
        CHECK(files == 1 && bytes == 5000);
        gn_meter_begin(&mt, GN_ENHANCED, bytes);
        CHECK(mt.total == 15000);
        gn_meter_progress(&mt, 2, 3, 2500, 5000);
        CHECK(mt.current == 7500);
        CHECK(gn_meter_fraction(&mt) > 0.49 && gn_meter_fraction(&mt) < 0.51);
        gn_meter_file_done(&mt);
        CHECK(gn_meter_fraction(&mt) == 1.0);
        gn_format_duration(3725.0, d, sizeof d);
        CHECK(strcmp(d, "1 h 02 min") == 0);
        gn_format_duration(200.0, d, sizeof d);
        CHECK(strcmp(d, "3 min 20 s") == 0);
        gn_format_duration(-1.0, d, sizeof d);
        CHECK(strcmp(d, "--") == 0);
        CHECK(gn_wipe_file(path, GN_STANDARD, 0, NULL, NULL) == GN_OK);
    }

    /* A folder: refused without GN_RECURSIVE, gone with it. */
    make_dir("gn-dir");
    make_dir("gn-dir/sub");
    write_file("gn-dir/a.bin", 100);
    write_file("gn-dir/sub/b.bin", 5000);
    CHECK(gn_wipe_path("gn-dir", GN_STANDARD, 0, NULL, NULL, NULL) == GN_ERR_NOT_FILE);
    CHECK(exists("gn-dir/a.bin"));
    g_files = 0;
    CHECK(gn_wipe_path("gn-dir", GN_ENHANCED, GN_RECURSIVE, on_file, NULL, NULL) == GN_OK);
    CHECK(g_files == 4);   /* two files and two folders */
    CHECK(!exists("gn-dir/sub/b.bin"));
    CHECK(make_dir("gn-dir") == 0);   /* it was removed, so it can be made again */
    CHECK(gn_wipe_path("gn-dir", GN_STANDARD, GN_RECURSIVE, NULL, NULL, NULL) == GN_OK);

    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures != 0;
}
