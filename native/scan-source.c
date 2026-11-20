/* ProfitPilot bounded stdin scanner. The actual detection engine is the signed
 * distribution libclamav package; this adapter supplies no detection rules. */
#include <clamav.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SOURCE_BYTES (512U * 1024U)
#define DATABASE_DIR "/var/lib/clamav"
int main(int argc, char **argv) {
    (void)argv;
    if (argc != 1) return 2;
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
    if (cl_load(DATABASE_DIR, engine, &signatures, CL_DB_STDOPT) != CL_SUCCESS || signatures == 0) goto done;
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
