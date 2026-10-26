/*
 * Entropy source of OpenSSL for Windows NT 3.x. It is used in place of
 * rand_win.c in a configuration that defines OPENSSL_RAND_SEED_NT31
 * (Configurations/50-nt31.conf).
 *
 * Windows NT 3.1 and 3.51 have no system random number generator: the
 * CryptoAPI came with Windows NT 4.0. This file does the same as OpenSSL
 * before version 1.1.0 did on such systems: it collects system data that an
 * attacker cannot easily know (performance counters of the whole system,
 * timing variations, memory and input state) and gives a hash of it to the
 * OpenSSL generator. The entropy that it claims is an estimate, not a
 * measured value. Do not use it where the quality of the random numbers is
 * critical.
 *
 * On a system that has the CryptoAPI (found at run time), the system
 * generator is used and the collection is not necessary.
 */

#include "internal/cryptlib.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "crypto/rand_pool.h"
#include "crypto/rand.h"
#include "prov/seeding.h"

#if defined(OPENSSL_RAND_SEED_NT31)

# include <windows.h>

# define NT31_PROV_RSA_FULL 1
# define NT31_CRYPT_VERIFYCONTEXT 0xF0000000u

typedef BOOL (WINAPI *acquire_context_fn)(ULONG *provider, const char *container,
                                          const char *name, DWORD type,
                                          DWORD flags);
typedef BOOL (WINAPI *gen_random_fn)(ULONG provider, DWORD length,
                                     BYTE *buffer);
typedef BOOL (WINAPI *release_context_fn)(ULONG provider, DWORD flags);

/* Returns 1 if the system generator filled the buffer. */
static int system_random(unsigned char *buffer, size_t length)
{
    HMODULE advapi = LoadLibraryA("advapi32.dll");
    acquire_context_fn acquire;
    gen_random_fn generate;
    release_context_fn release;
    ULONG provider;
    int ok = 0;

    if (advapi == NULL)
        return 0;
    acquire = (acquire_context_fn)GetProcAddress(advapi, "CryptAcquireContextA");
    generate = (gen_random_fn)GetProcAddress(advapi, "CryptGenRandom");
    release = (release_context_fn)GetProcAddress(advapi, "CryptReleaseContext");
    if (acquire != NULL && generate != NULL && release != NULL
        && acquire(&provider, NULL, NULL, NT31_PROV_RSA_FULL,
                   NT31_CRYPT_VERIFYCONTEXT)) {
        ok = generate(provider, (DWORD)length, buffer) != 0;
        release(provider, 0);
    }
    FreeLibrary(advapi);
    return ok;
}

/* Adds the hash of the data; entropy_bits is the estimate for all of it. */
static void add_hashed(RAND_POOL *pool, const void *data, size_t length,
                       size_t entropy_bits)
{
    unsigned char digest[SHA512_DIGEST_LENGTH];

    if (ossl_rand_pool_bytes_remaining(pool) < sizeof(digest))
        return;
    SHA512(data, length, digest);
    ossl_rand_pool_add(pool, digest, sizeof(digest), entropy_bits);
    OPENSSL_cleanse(digest, sizeof(digest));
}

/*
 * The performance data of the system: counters of all processes, threads,
 * disks, network interfaces and of the memory manager.
 */
static void add_performance_data(RAND_POOL *pool)
{
    DWORD size = 65536;
    unsigned char *buffer = NULL;
    LONG status = ERROR_MORE_DATA;

    while (status == ERROR_MORE_DATA && size <= 4 * 1024 * 1024) {
        unsigned char *bigger = OPENSSL_realloc(buffer, size);
        DWORD length = size;

        if (bigger == NULL)
            break;
        buffer = bigger;
        status = RegQueryValueExA(HKEY_PERFORMANCE_DATA, "Global", NULL, NULL,
                                  buffer, &length);
        if (status == ERROR_SUCCESS) {
            /* Four parts, so that no part hides the others in one hash. */
            size_t part = length / 4;
            int i;

            for (i = 0; i < 4 && part > 0; i++)
                add_hashed(pool, buffer + i * part, part, 32);
        }
        size *= 2;
    }
    RegCloseKey(HKEY_PERFORMANCE_DATA);
    OPENSSL_free(buffer);
}

/*
 * The time that a yield to the scheduler takes, in units of the performance
 * counter. One quarter of a bit is estimated for each sample.
 */
static void add_timing(RAND_POOL *pool)
{
    LARGE_INTEGER samples[256];
    int i;

    for (i = 0; i < 256; i++) {
        Sleep(0);
        QueryPerformanceCounter(&samples[i]);
    }
    add_hashed(pool, samples, sizeof(samples), 64);
}

static void add_state(RAND_POOL *pool)
{
    struct {
        MEMORYSTATUS memory;
        POINT cursor;
        SYSTEMTIME time;
        FILETIME created, exited, kernel, user;
        DWORD ticks, process, thread;
        void *stack;
        DWORD free_clusters, clusters, sectors, bytes;
    } state;

    memset(&state, 0, sizeof(state));
    state.memory.dwLength = sizeof(state.memory);
    GlobalMemoryStatus(&state.memory);
    GetCursorPos(&state.cursor);
    GetSystemTime(&state.time);
    GetProcessTimes(GetCurrentProcess(), &state.created, &state.exited,
                    &state.kernel, &state.user);
    state.ticks = GetTickCount();
    state.process = GetCurrentProcessId();
    state.thread = GetCurrentThreadId();
    state.stack = &state;
    GetDiskFreeSpaceA(NULL, &state.sectors, &state.bytes, &state.free_clusters,
                      &state.clusters);
    add_hashed(pool, &state, sizeof(state), 16);
}

size_t ossl_pool_acquire_entropy(RAND_POOL *pool)
{
    size_t bytes_needed = ossl_rand_pool_bytes_needed(pool, 1);
    unsigned char *buffer = ossl_rand_pool_add_begin(pool, bytes_needed);
    int round;

    if (buffer != NULL) {
        size_t bytes = system_random(buffer, bytes_needed) ? bytes_needed : 0;

        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        if (bytes > 0)
            return ossl_rand_pool_entropy_available(pool);
    }

    add_state(pool);
    add_performance_data(pool);
    for (round = 0; round < 16 && ossl_rand_pool_entropy_needed(pool) > 0; round++)
        add_timing(pool);
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
