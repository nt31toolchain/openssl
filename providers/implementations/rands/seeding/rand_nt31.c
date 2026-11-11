/*
 * Entropy source of OpenSSL for Windows NT 3.x. It is used in place of
 * rand_win.c in a configuration that defines OPENSSL_RAND_SEED_NT31
 * (Configurations/50-nt31.conf).
 *
 * The seed comes from RtlGenRandom of the Windows API layer of the NT 3.1
 * SDK toolchain (nt31_winapi.lib): the generator of the system where the
 * system has one (Windows NT 4.0 and later), and the generator of the
 * layer on Windows NT 3.1 and 3.51, which have none. That generator
 * collects system data that an attacker cannot easily know (counters of
 * the whole system, timing variations, memory and input state); its
 * entropy is an estimate, not a measured value. Do not use it where the
 * quality of the random numbers is critical.
 *
 */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include "crypto/rand_pool.h"
#include "crypto/rand.h"
#include "prov/seeding.h"

#if defined(OPENSSL_RAND_SEED_NT31)

# include <windows.h>

/* The export name of RtlGenRandom. */
BOOLEAN WINAPI SystemFunction036(PVOID buffer, ULONG size);

size_t ossl_pool_acquire_entropy(RAND_POOL *pool)
{
    size_t bytes_needed = ossl_rand_pool_bytes_needed(pool, 1);
    unsigned char *buffer = ossl_rand_pool_add_begin(pool, bytes_needed);

    if (buffer != NULL) {
        size_t bytes = SystemFunction036(buffer, (ULONG)bytes_needed) ? bytes_needed : 0;

        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
    }
    return ossl_rand_pool_entropy_available(pool);
}

int ossl_pool_add_nonce_data(RAND_POOL *pool)
{
    struct {
        DWORD pid;
        DWORD tid;
        SYSTEMTIME time;
        LARGE_INTEGER counter;
    } data;

    /* Erase the entire structure including any padding */
    memset(&data, 0, sizeof(data));
    data.pid = GetCurrentProcessId();
    data.tid = GetCurrentThreadId();
    GetSystemTime(&data.time);
    QueryPerformanceCounter(&data.counter);

    return ossl_rand_pool_add(pool, (unsigned char *)&data, sizeof(data), 0);
}

int ossl_rand_pool_init(void)
{
    return 1;
}

void ossl_rand_pool_cleanup(void)
{
}

void ossl_rand_pool_keep_random_devices_open(int keep)
{
}

#endif
