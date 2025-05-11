#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "account.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "banned.h"

int main(void) {
    dprintf(STDOUT_FILENO, "=== Testing account_create and account_free ===\n\n");
    
    // Test 1: Valid account creation
    dprintf(STDOUT_FILENO, "Test 1: Creating account with valid parameters...\n");
    account_t *account = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    
    if (account == NULL) {
        dprintf(STDOUT_FILENO, "FAIL: Failed to create account with valid parameters\n");
        return 1;
    }
    
    dprintf(STDOUT_FILENO, "PASS: Account created successfully\n");
    dprintf(STDOUT_FILENO, "User ID: %s\n", account->userid);
    dprintf(STDOUT_FILENO, "Email: %s\n", account->email);
    dprintf(STDOUT_FILENO, "Birthdate: %s\n", account->birthdate);
    
    // Test 2: Check that default fields are set correctly
    dprintf(STDOUT_FILENO, "\nTest 2: Checking default fields...\n");
    int default_fields_ok = 1;
    
    if (account->login_count != 0) {
        dprintf(STDOUT_FILENO, "FAIL: login_count should be 0, found %u\n", account->login_count);
        default_fields_ok = 0;
    }
    
    if (account->login_fail_count != 0) {
        dprintf(STDOUT_FILENO, "FAIL: login_fail_count should be 0, found %u\n", account->login_fail_count);
        default_fields_ok = 0;
    }
    
    if (account->unban_time != 0) {
        dprintf(STDOUT_FILENO, "FAIL: unban_time should be 0, found %ld\n", account->unban_time);
        default_fields_ok = 0;
    }
    
    if (account->expiration_time != 0) {
        dprintf(STDOUT_FILENO, "FAIL: expiration_time should be 0, found %ld\n", account->expiration_time);
        default_fields_ok = 0;
    }
    
    if (default_fields_ok) {
        dprintf(STDOUT_FILENO, "PASS: All default fields set correctly\n");
    }
    
    // Test 3: Test account_free with valid account
    dprintf(STDOUT_FILENO, "\nTest 3: Freeing account...\n");
    account_free(account);
    dprintf(STDOUT_FILENO, "PASS: Account freed without crashing\n");
    
    // Test 4: Test account_free with NULL
    dprintf(STDOUT_FILENO, "\nTest 4: Freeing NULL account...\n");
    account_free(NULL);
    dprintf(STDOUT_FILENO, "PASS: NULL account handling works\n");
    
    // Test 5: Test invalid parameters
    dprintf(STDOUT_FILENO, "\nTest 5: Testing invalid parameters...\n");
    
    dprintf(STDOUT_FILENO, "Testing NULL userid...\n");
    account = account_create(NULL, "password123", "test@example.com", "1990-01-01");
    if (account == NULL) {
        dprintf(STDOUT_FILENO, "PASS: NULL userid correctly rejected\n");
    } else {
        dprintf(STDOUT_FILENO, "FAIL: NULL userid was accepted\n");
        account_free(account);
    }
    
    dprintf(STDOUT_FILENO, "Testing invalid birthdate...\n");
    account = account_create("testuser", "password123", "test@example.com", "1990-13-01");
    if (account == NULL) {
        dprintf(STDOUT_FILENO, "PASS: Invalid birthdate correctly rejected\n");
    } else {
        dprintf(STDOUT_FILENO, "FAIL: Invalid birthdate was accepted\n");
        account_free(account);
    }
    
    dprintf(STDOUT_FILENO, "\n=== Tests completed successfully ===\n");
    return 0;
}
