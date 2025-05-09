#define CITS3007_PERMISSIVE

#include <stdio.h>
#include <time.h>
#include "account.h"
// THis is just to test the ban, expire and account create funtions
int main() {
    // Create an account (valid birthdate assumed)
    account_t *acc = account_create("Min", "abc123", "min@mail.com", "2001-01-01");
    if (!acc) {
        printf("Failed to create account.\n");
        return 1;
    }
    if (!acc) {
        printf("Failed to create account.\n");
        return 1;
    }

    printf("Account created for user: %s\n", acc->userid);

    time_t now = time(NULL);

    printf("\nIs account banned in creation? ➜ %s", account_is_banned(acc) ? "Yes" : "No");
    // Set the unban time to 1 minute in the future
    account_set_unban_time(acc, now + 60);
    printf("\nAccount will be unbanned in 60 seconds...\n");
    printf("Is account banned? ➜ %s\n", account_is_banned(acc) ? "Yes" : "No");

    // Set the unban time to 1 minute in the past (should now be unbanned)
    account_set_unban_time(acc, now - 60);
    printf("Resetting unban time to the past...\n");
    printf("Is account banned? ➜ %s\n", account_is_banned(acc) ? "Yes" : "No");

    printf("\nIs account expired in creation? ➜ %s", account_is_expired(acc) ? "Yes" : "No");
    // Set expiration time 1 minute in the future (should still be valid)
    account_set_expiration_time(acc, now + 60);
    printf("\nAccount will expire in 60 seconds...\n");
    printf("Is account expired? ➜ %s\n", account_is_expired(acc) ? "Yes" : "No");

    // Set expiration time 1 minute in the past (should be expired now)
    account_set_expiration_time(acc, now - 60);
    printf("Resetting expiration time to the past...\n");
    printf("Is account expired? ➜ %s\n", account_is_expired(acc) ? "Yes" : "No");

    account_free(acc);
    return 0;
}
