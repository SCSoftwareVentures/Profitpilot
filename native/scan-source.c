/* ProfitPilot bounded stdin scanner. The actual detection engine is the signed
 * distribution libclamav package; this adapter supplies no detection rules. */
#define _POSIX_C_SOURCE 200809L
#include <clamav.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/resource.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SOURCE_BYTES (512U * 1024U)
#define DATABASE_DIR "/var/lib/clamav"
#ifndef PROFITPILOT_FIXTURE_ONLY
/* Protected scanner accepts only full vendor-signed CVD archives on an operator-managed immutable mount. */
static int load_vendor_databases(struct cl_engine *engine, unsigned int *signatures) {
    static const char *const paths[] = {DATABASE_DIR "/main.cvd", DATABASE_DIR "/daily.cvd", DATABASE_DIR "/bytecode.cvd"};
    struct statvfs fs;
    if (statvfs(DATABASE_DIR, &fs) != 0 || !(fs.f_flag & ST_RDONLY)) return 0;
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        struct stat st;
        if (lstat(paths[i], &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 512LL*1024LL*1024LL) return 0;
        if (cl_cvdverify(paths[i]) != CL_SUCCESS) return 0;
        if (i == 1) {
            struct cl_cvd *header = cl_cvdhead(paths[i]);
            if (!header) return 0;
            time_t now = time(NULL);
            double age = difftime(now, (time_t)header->stime);
            cl_cvdfree(header);
            if (now == (time_t)-1 || age < -300.0 || age > 259200.0) return 0;
        }
        if (cl_load(paths[i], engine, signatures, CL_DB_STDOPT | CL_DB_OFFICIAL_ONLY) != CL_SUCCESS) return 0;
    }
    return *signatures > 0;
}
#endif
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 2;
    const struct rlimit cpu = {90, 90}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) != 0 || setrlimit(RLIMIT_CORE, &core) != 0) return 2;
    int exit_code = 2;
    unsigned int signatures = 0;
    unsigned char *bytes = malloc(MAX_SOURCE_BYTES + 1U);
    struct cl_engine *engine = NULL;
    cl_fmap_t *map = NULL;
    if (!bytes) return 2;
    size_t size = fread(bytes, 1, MAX_SOURCE_BYTES + 1U, stdin);
    if (ferror(stdin) || !feof(stdin) || size == 0 || size > MAX_SOURCE_BYTES) goto done;
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) goto done;
    engine = cl_engine_new();
    if (!engine) goto done;
    if (cl_engine_set_str(engine, CL_ENGINE_TMPDIR, "/tmp") != CL_SUCCESS) goto done;
#ifdef PROFITPILOT_FIXTURE_ONLY
    if (cl_load(DATABASE_DIR, engine, &signatures, CL_DB_STDOPT) != CL_SUCCESS || signatures == 0) goto done;
#else
    if (!load_vendor_databases(engine, &signatures)) goto done;
#endif
    if (cl_engine_compile(engine) != CL_SUCCESS) goto done;
    struct cl_scan_options options = {0};
    options.general = CL_SCAN_GENERAL_HEURISTICS;
    options.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF |
                    CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_XMLDOCS |
                    CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML |
                    CL_SCAN_PARSE_PE | CL_SCAN_PARSE_ONENOTE | CL_SCAN_PARSE_IMAGE |
                    CL_SCAN_PARSE_IMAGE_FUZZY_HASH;
    options.heuristic = CL_SCAN_HEURISTIC_EXCEEDS_MAX | CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
                        CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
    map = cl_fmap_open_memory(bytes, size);
    if (!map) goto done;
    const char *virus = NULL;
    unsigned long scanned = 0;
    cl_error_t verdict = cl_scanmap_callback(map, "source.csv", &virus, &scanned, engine, &options, NULL);
    if (verdict == CL_CLEAN) exit_code = 0;
    else if (verdict == CL_VIRUS) exit_code = 1;
done:
    if (map) cl_fmap_close(map);
    if (engine && cl_engine_free(engine) != CL_SUCCESS) exit_code = 2;
    free(bytes);
    return exit_code;
}
