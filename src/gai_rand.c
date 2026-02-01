#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
// only required for seeding srand
// #include <time.h>
#include <stdlib.h>
#include <netdb.h>

typedef enum {
    ADDR_PREF_EQUAL = 0,  // no preference, shuffle all
    ADDR_PREF_IPV4,       // IPv4 first (random inside group), then others
    ADDR_PREF_IPV6        // IPv6 first (random inside group), then others
} addr_pref_t;

static void fisher_yates(struct addrinfo **arr, size_t n)
{
    /* Not need for <2 item */
    if (n < 2)
        return;

    for (size_t i = n - 1; i > 0; i--) {
        size_t j = (size_t)(rand() % (i + 1));  // 0 <= j <= i
        struct addrinfo *tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static int is_preferred(const struct addrinfo *ai, addr_pref_t pref)
{
    if (pref == ADDR_PREF_IPV4) {
        return (ai->ai_family == AF_INET);
    } else if (pref == ADDR_PREF_IPV6) {
        return (ai->ai_family == AF_INET6);
    } else {
	/* Other, unknown address types */
        return -1;
    }
}

/*
 * Shuffle the order of an addrinfo list in-place,
 * with optional preference for IPv4 or IPv6.
 *
 *  pref == ADDR_PREF_EQUAL:
 *      all addresses shuffled together
 *
 *  pref == ADDR_PREF_IPV4:
 *      IPv4 addresses come first (randomized among themselves),
 *      then all non-IPv4 (IPv6/others), randomized among themselves.
 *
 *  pref == ADDR_PREF_IPV6:
 *      IPv6 addresses come first (randomized among themselves),
 *      then all non-IPv6 (IPv4/others), randomized among themselves.
 *
 * NOTE: Seed RNG once e.g.:
 *   srand((unsigned)time(NULL));
 *
 */
void shuffle_addrinfo(struct addrinfo **res, addr_pref_t pref)
{
    if (res == NULL || *res == NULL)
        return;

    struct addrinfo *cur;
    size_t n = 0;

    /* First, count nodes */
    for (cur = *res; cur; cur = cur->ai_next)
        n++;

    /* Less than 2, not need to shuffle */
    if (n < 2)
        return;

    // srand is already seeded in prog.c
    // srand((unsigned)time(NULL));

    /* v4 and v6 addresses are equals, shuffle all */
    if (pref == ADDR_PREF_EQUAL) {
        struct addrinfo **arr = malloc(n * sizeof(*arr));
        if (!arr)
            return;

        size_t i = 0;
        for (cur = *res; cur; cur = cur->ai_next)
            arr[i++] = cur;

        fisher_yates(arr, n);

        for (i = 0; i < n - 1; i++)
            arr[i]->ai_next = arr[i + 1];
        arr[n - 1]->ai_next = NULL;

        *res = arr[0];
        free(arr);
        return;
    }

    /* Preference mode: partition into preferred + others */
    size_t n_pref = 0, n_other = 0;

    for (cur = *res; cur; cur = cur->ai_next) {
        if (is_preferred(cur, pref))
            n_pref++;
        else
            n_other++;
    }

    struct addrinfo **pref_arr  = malloc(n_pref  * sizeof(*pref_arr));
    struct addrinfo **other_arr = malloc(n_other * sizeof(*other_arr));
    if (!pref_arr || !other_arr) {
        free(pref_arr);
        free(other_arr);
        return;
    }

    size_t ip = 0, io = 0;
    for (cur = *res; cur; cur = cur->ai_next) {
        if (is_preferred(cur, pref)==1)
            pref_arr[ip++] = cur;
        else if (is_preferred(cur, pref)==0)
            other_arr[io++] = cur;
    }

    /* Shuffle each group separately */
    fisher_yates(pref_arr, n_pref);
    fisher_yates(other_arr, n_other);

    /* Rebuild list: preferred first, then others */
    struct addrinfo *head = NULL;
    struct addrinfo *tail = NULL;

    for (size_t i = 0; i < n_pref; i++) {
        if (!head)
            head = pref_arr[i];
        else
            tail->ai_next = pref_arr[i];
        tail = pref_arr[i];
    }

    for (size_t i = 0; i < n_other; i++) {
        if (!head)
            head = other_arr[i];
        else
            tail->ai_next = other_arr[i];
        tail = other_arr[i];
    }

    if (tail)
        tail->ai_next = NULL;

    *res = head;

    free(pref_arr);
    free(other_arr);
}
