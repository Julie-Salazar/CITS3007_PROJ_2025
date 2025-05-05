#include "../src/account.h"
#include <stdio.h>

void test_account_update_password(account_t *acc, const char *new_plaintext_password) {
    
    printf("Starting password update test.\n");
    printf("Updating password to: %s\n", new_plaintext_password);

    bool result = account_update_password(acc, new_plaintext_password);

    if (result != true) {
        printf("Test result: FAIL\n");
        printf("Salt generation or password hashing failed.\n");
    }
    else if (account_validate_password(acc, new_plaintext_password)) {
        printf("Test resault: PASS\n");
    }
    else {
        printf("Test result: FAIL\n");
        printf("New password validation failed.\n");
    }

    printf("----------------------------------------\n");

}

void test_account_validate_password(const account_t *acc, const char *plaintext_password, bool expected_output) {
    printf("Starting password validation test.\n");
    printf("Attempted password: %s\n", plaintext_password);
    
    bool result = account_validate_password(acc, plaintext_password);

    if (result == expected_output) {
        printf("Test result: PASS\n");
    }
    else {
        printf("Test result: FAIL\n");
        printf("\nExpected result: %d\n", expected_output);
        printf("Actual result: %d\n", result);
    }
    printf("----------------------------------------\n");
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
    
    printf("Starting password function tests.");
    printf("----------------------------------------\n");

    test_account_update_password(&test_acc, new_pw);

    test_account_validate_password(&test_acc, "secure_password", true);
    test_account_validate_password(&test_acc, "wrong_password", false);

    printf("Password function tests complete.\n");
    return 0;
}