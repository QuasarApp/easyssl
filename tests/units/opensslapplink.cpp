//#
//# Copyright (C) 2026 QuasarApp.
//# Distributed under the GPLv3 software license, see the accompanying
//# Everyone is permitted to copy and distribute verbatim copies
//# of this license document, but changing is not allowed.
//#

#if defined(_WIN32)

#include <fcntl.h>
#include <io.h>
#include <stdio.h>

/*
 * OpenSSL for Windows (MSYS2/MinGW as well as Win64OpenSSL) is built with
 * the "uplink" mechanism enabled by default (OPENSSL_USE_APPLINK, see the
 * OpenSSL crypto/build.info). In such builds, file BIOs that wrap a FILE*
 * (BIO_new_fp()/BIO_set_fp() - used internally by OpenSSL, e.g. in
 * ERR_print_errors_fp(), CONF_load_fp() or the SSLKEYLOGFILE handling)
 * dispatch their stdio calls through lazy stubs. The stubs resolve the
 * target functions at runtime by looking up the "OPENSSL_Applink" export
 * in the main executable:
 *
 *     GetProcAddress(GetModuleHandle(NULL), "OPENSSL_Applink");
 *
 * If the executable does not provide that export, OpenSSL prints
 *
 *     OPENSSL_Uplink(<table address>,<index>): no OPENSSL_Applink
 *
 * and immediately calls TerminateProcess(GetCurrentProcess(), 1), killing
 * the process with no way to recover. This is what crashed the test
 * executable on Windows (exit code 1) right after the ECDSA test.
 *
 * OpenSSL ships ms/applink.c in its source tree for exactly this purpose:
 * the host application is supposed to compile it in and export
 * OPENSSL_Applink() (OpenSSL's own Windows unit tests link it in).
 * This file is a self-contained equivalent of ms/applink.c with the same
 * table layout, so the test executable satisfies the uplink contract
 * without requiring the OpenSSL source tree.
 */

#define APPLINK_STDIN 1
#define APPLINK_STDOUT 2
#define APPLINK_STDERR 3
#define APPLINK_FPRINTF 4
#define APPLINK_FGETS 5
#define APPLINK_FREAD 6
#define APPLINK_FWRITE 7
#define APPLINK_FSETMOD 8
#define APPLINK_FEOF 9
#define APPLINK_FCLOSE 10 /* should not be used */

#define APPLINK_FOPEN 11 /* solely for completeness */
#define APPLINK_FSEEK 12
#define APPLINK_FTELL 13
#define APPLINK_FFLUSH 14
#define APPLINK_FERROR 15
#define APPLINK_CLEARERR 16
#define APPLINK_FILENO 17 /* to be used with below */

#define APPLINK_OPEN 18 /* formally can't be used, as flags can vary */
#define APPLINK_READ 19
#define APPLINK_WRITE 20
#define APPLINK_LSEEK 21
#define APPLINK_CLOSE 22
#define APPLINK_MAX 22 /* always same as last macro */

namespace {

void *app_stdin() {
    return (void *)stdin;
}

void *app_stdout() {
    return (void *)stdout;
}

void *app_stderr() {
    return (void *)stderr;
}

int app_feof(FILE *fp) {
    return feof(fp);
}

int app_ferror(FILE *fp) {
    return ferror(fp);
}

void app_clearerr(FILE *fp) {
    clearerr(fp);
}

int app_fileno(FILE *fp) {
    return _fileno(fp);
}

int app_fsetmod(FILE *fp, char mod) {
    return _setmode(_fileno(fp), mod == 'b' ? _O_BINARY : _O_TEXT);
}

// The table layout must match ms/applink.c from the OpenSSL source tree.
// Index 0 must always hold APPLINK_MAX.
void *kApplinkTable[] = {
    (void *)APPLINK_MAX,
    (void *)app_stdin,  // APPLINK_STDIN
    (void *)app_stdout, // APPLINK_STDOUT
    (void *)app_stderr, // APPLINK_STDERR
    (void *)fprintf,    // APPLINK_FPRINTF
    (void *)fgets,      // APPLINK_FGETS
    (void *)fread,      // APPLINK_FREAD
    (void *)fwrite,     // APPLINK_FWRITE
    (void *)app_fsetmod, // APPLINK_FSETMOD
    (void *)app_feof,    // APPLINK_FEOF
    (void *)fclose,      // APPLINK_FCLOSE
    (void *)fopen,       // APPLINK_FOPEN
    (void *)fseek,       // APPLINK_FSEEK
    (void *)ftell,       // APPLINK_FTELL
    (void *)fflush,      // APPLINK_FFLUSH
    (void *)app_ferror,   // APPLINK_FERROR
    (void *)app_clearerr, // APPLINK_CLEARERR
    (void *)app_fileno,   // APPLINK_FILENO
    (void *)_open,        // APPLINK_OPEN
    (void *)_read,        // APPLINK_READ
    (void *)_write,       // APPLINK_WRITE
    (void *)_lseek,       // APPLINK_LSEEK
    (void *)_close        // APPLINK_CLOSE
};

} // namespace

extern "C" {

// Expected by OpenSSL (ms/uplink.c) in uplink-enabled Windows builds.
__declspec(dllexport) void **OPENSSL_Applink() {
    return kApplinkTable;
}

} // extern "C"

#endif // defined(_WIN32)
