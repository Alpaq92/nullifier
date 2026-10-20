/* Grand Nullifier: overwrite a file in place, then rename, truncate and delete it.
 *
 * Pure C11, no dependencies; Windows, Linux, macOS and the BSDs. Paths are
 * UTF-8 everywhere.
 *
 * What it cannot do: on SSDs and other flash (wear levelling), on copy-on-write
 * or snapshotting file systems (APFS, Btrfs, ZFS, Windows shadow copies) and in
 * cloud-synced folders, old copies of the data can survive elsewhere, whatever
 * the number of passes. There only full-disk encryption makes deletion reliable. */
#ifndef GRANDNULLIFIER_H
#define GRANDNULLIFIER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GN_VERSION "0.1.0"

typedef enum gn_method {
    GN_STANDARD = 0,   /* NIST SP 800-88 Clear: 1 random pass */
    GN_ENHANCED,       /* US Air Force AFSSI-5020: 0x00, 0xFF, random */
    GN_PROFESSIONAL,   /* RCMP TSSIT OPS-II: 0x00/0xFF x3, random, verified */
    GN_ULTIMATE,       /* Pfitzner: 33 random passes */
    GN_METHOD_COUNT
} gn_method;

typedef struct gn_method_info {
    const char *alias;     /* "Standard" */
    const char *key;       /* "standard", for command lines and settings */
    const char *standard;  /* "NIST SP 800-88 Clear" */
    int         passes;
    int         verify;    /* the last pass is read back */
} gn_method_info;

enum {
    GN_OK = 0,
    GN_ERR_ARG = -1,        /* bad method or path */
    GN_ERR_NOT_FILE = -2,   /* a directory, link or device: never followed */
    GN_ERR_OPEN = -3,
    GN_ERR_WRITE = -4,
    GN_ERR_VERIFY = -5,     /* the read-back did not match */
    GN_ERR_REMOVE = -6,     /* overwritten, but could not be deleted */
    GN_ERR_CANCELLED = -7,
    GN_ERR_RANDOM = -8      /* no system random source */
};

/* Overwrite only: no rename, truncate or delete. For tests. */
#define GN_KEEP 1u

/* Called often while writing. pass runs 1..passes, then once more for the
 * read-back of a verifying method (pass == passes + 1 of passes + 1).
 * Return non-zero to stop; the file is then left partly overwritten, still
 * in place. */
typedef int (*gn_progress_fn)(void *user, int pass, int passes,
                              uint64_t done, uint64_t total);

const gn_method_info *gn_method_get(gn_method m);
/* By key ("ultimate") or alias, case-insensitive; -1 when unknown. */
int  gn_method_find(const char *name);

int  gn_wipe_file(const char *path, gn_method m, unsigned flags,
                  gn_progress_fn progress, void *user);
const char *gn_strerror(int rc);

/* With gn_wipe_path: wipe a folder's files, then remove its folders. */
#define GN_RECURSIVE 2u
/* gn_file_fn's rc before a file is wiped; afterwards it gets GN_OK or an error. */
#define GN_STARTING 1

/* Called before and after each file, and after each folder or link it
 * removes (or cannot). Return non-zero from a GN_STARTING call to stop. */
typedef int (*gn_file_fn)(void *user, const char *path, int rc);

/* A file, or with GN_RECURSIVE a folder and everything in it. Links and
 * junctions inside are removed, never followed. GN_OK when everything went;
 * otherwise the first error, after trying the rest. */
int  gn_wipe_path(const char *path, gn_method m, unsigned flags, gn_file_fn on_file,
                  gn_progress_fn progress, void *user);

/* ---- progress and time left --------------------------------------------- */

/* Adds what gn_wipe_path would wipe (same flags) to *files and *bytes. */
void gn_measure(const char *path, unsigned flags, uint64_t *files, uint64_t *bytes);

/* Overall progress across files and passes. Feed it from the callbacks:
 * gn_meter_progress from gn_progress_fn, gn_meter_file_done when gn_file_fn
 * reports a file finished (whatever its rc). */
typedef struct gn_meter {
    uint64_t total;       /* bytes to write (and read back): file bytes x steps */
    uint64_t base;        /* written by finished files */
    uint64_t current;     /* base plus the file in progress */
    uint64_t file_size;   /* the file in progress */
    int      file_passes;
    double   started;     /* seconds, monotonic */
    double   rate;        /* bytes a second, smoothed */
    double   rate_at;
    uint64_t rate_bytes;
} gn_meter;

void   gn_meter_begin(gn_meter *mt, gn_method m, uint64_t bytes);
void   gn_meter_progress(gn_meter *mt, int pass, int passes, uint64_t done, uint64_t total);
void   gn_meter_file_done(gn_meter *mt);
/* 0..1 */
double gn_meter_fraction(const gn_meter *mt);
/* Seconds left; negative until there is enough to go on (about a second). */
double gn_meter_eta(const gn_meter *mt);
double gn_meter_elapsed(const gn_meter *mt);
/* "1 h 05 min", "3 min 20 s", "12 s"; "--" for a negative time. */
void   gn_format_duration(double seconds, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
