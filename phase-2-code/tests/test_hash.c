#include "../src/account.h"
#include "../src/logging.h"
#include <stdio.h>

void test_account_update_password(account_t *acc, const char *new_plaintext_password) {
    
    log_message(LOG_DEBUG, "Starting password update test.");
    log_message(LOG_DEBUG, "Updating password to: %s", new_plaintext_password);

    bool result = account_update_password(acc, new_plaintext_password);

    if (result != true) {
        log_message(LOG_DEBUG, "Test result: FAIL");
        log_message(LOG_DEBUG, "Salt generation or password hashing failed.");
    }
    else if (account_validate_password(acc, new_plaintext_password)) {
        log_message(LOG_DEBUG, "Test resault: PASS");
    }
    else {
        log_message(LOG_DEBUG, "Test result: FAIL");
        log_message(LOG_DEBUG, "New password validation failed.");
    }

    log_message(LOG_INFO, "----------------------------------------");

}

void test_account_validate_password(const account_t *acc, const char *plaintext_password, bool expected_output) {
    log_message(LOG_DEBUG, "Starting password validation test.");
    log_message(LOG_DEBUG, "Attempted password: %s", plaintext_password);
    
    bool result = account_validate_password(acc, plaintext_password);

    if (result == expected_output) {
        log_message(LOG_DEBUG, "Test result: PASS");
    }
    else {
        log_message(LOG_DEBUG, "Test result: FAIL");
        log_message(LOG_DEBUG, "\nExpected result: %d", expected_output);
        log_message(LOG_DEBUG, "Actual result: %d", result);
    }
    log_message(LOG_INFO, "----------------------------------------");
}

int main() {

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
    
    log_message(LOG_DEBUG, "Starting password function tests.");
    log_message(LOG_INFO, "----------------------------------------");

    test_account_update_password(&test_acc, new_pw);

    test_account_validate_password(&test_acc, "secure_password", true);
    test_account_validate_password(&test_acc, "wrong_password", false);

    log_message(LOG_DEBUG, "Password function tests complete.");
    return 0;
}