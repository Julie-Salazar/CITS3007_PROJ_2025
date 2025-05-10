#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include "account.h"

int main(void) {
    dprintf(STDOUT_FILENO, "Testing account creation...\n");
    
    account_t *acct = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    if (acct) {
        dprintf(STDOUT_FILENO, "Account created successfully!\n");
        account_free(acct);
        return 0;
    } else {
        dprintf(STDOUT_FILENO, "Failed to create account\n");
        return 1;
    }
}
