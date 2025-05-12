#define CITS3007_PERMISSIVE

#include "../src/account.h"
#include "../src/logging.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <check.h>

START_TEST (test_account_update_password) {
    
    account_t test_acc = {
        .account_id = 0,
        .userid = "test1",
        .password_hash = "no_hash_yet",
        .email = "test@example.com",
        .unban_time = 0,
        .expiration_time = 0,
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0,
        .birthdate = "0000-00-00"
    };
    
    char *new_pw = "secure_password";

    log_message(LOG_DEBUG, "Starting password update test.");
    log_message(LOG_DEBUG, "Updating password to: %s", new_pw);

    bool result = account_update_password(&test_acc, new_pw);

    ck_assert(result);

    ck_assert(account_validate_password(&test_acc, new_pw));

    log_message(LOG_DEBUG, "Test result: PASS");

}
END_TEST

START_TEST (test_account_validate_password) {

    account_t test_acc = {
        .account_id = 0,
        .userid = "test1",
        .password_hash = "no_hash_yet",
        .email = "test@example.com",
        .unban_time = 0,
        .expiration_time = 0,
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0,
        .birthdate = "0000-00-00"
    };

    char *new_pw = "correct_password";

    bool hash_result = account_update_password(&test_acc, new_pw);

    ck_assert(hash_result);
    
    log_message(LOG_DEBUG, "Starting password validation test.");
    
    bool result = account_validate_password(&test_acc, "correct_password");

    ck_assert(result);

    result = account_validate_password(&test_acc, "wrong_password");

    ck_assert(!result);

    log_message(LOG_DEBUG, "Test result: PASS");
}
END_TEST

START_TEST (test_unique_hash_generation) {
    
    account_t test_acc = {
        .account_id = 0,
        .userid = "test1",
        .password_hash = "no_hash_yet",
        .email = "test@example.com",
        .unban_time = 0,
        .expiration_time = 0,
        .login_count = 0,
        .login_fail_count = 0,
        .last_login_time = 0,
        .last_ip = 0,
        .birthdate = "0000-00-00"
    };

    bool hash_result = account_update_password(&test_acc, "test_password");

    ck_assert(hash_result);

    log_message(LOG_DEBUG, "Starting unique hash generation test.");

    // Store original password hash and ensure NULL termination
    char old_password_hash[HASH_LENGTH];
    strncpy(old_password_hash, test_acc.password_hash, HASH_LENGTH - 1);
    old_password_hash[HASH_LENGTH - 1] = '\0';

    hash_result = account_update_password(&test_acc, "test_password");

    ck_assert(hash_result);

    // Store new password hash for same password and ensure NULL termination
    char new_password_hash[HASH_LENGTH];
    strncpy(new_password_hash, test_acc.password_hash, HASH_LENGTH - 1);
    new_password_hash[HASH_LENGTH - 1] = '\0';

    int comp_result = strncmp(old_password_hash, new_password_hash, HASH_LENGTH - 1);

    ck_assert_int_ne(comp_result, 0);

    log_message(LOG_DEBUG, "Test result: PASS");
    
}
END_TEST