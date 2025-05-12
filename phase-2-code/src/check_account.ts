#define _GNU_SOURCE
#define _POSIX_C_SOURCE 199506L
#define CITS3007_PERMISSIVE

#include <check.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "account.h"
#include "logging.h"

#define ARR_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Helper function for setup
void print_test_starting(const char* test_name) {
    printf("\n==== STARTING TEST: %s ====\n", test_name);
}

#suite account_suite

#tcase account_create_test_case

#test test_account_create_works
    print_test_starting("test_account_create_works");
    
    const char* userid = "someuser";
    const char* email = "foo@bar.com";
    const char* plaintext_password = "password123";
    const char* birthdate = "1990-01-01";

    account_t *res = account_create(userid, plaintext_password,
                          email, birthdate
                          );

    // Verify account was created
    ck_assert_ptr_ne(res, NULL);
    
    // Check basic account properties
    ck_assert_str_eq(res->userid, userid);
    ck_assert_str_eq(res->email, email);
    ck_assert_int_eq(memcmp(res->birthdate, birthdate, BIRTHDATE_LENGTH), 0);
    
    // Password should be hashed (not stored as plaintext)
    char copy_of_hash[HASH_LENGTH + 1] = { 0 };
    memcpy(copy_of_hash, res->password_hash, HASH_LENGTH);
    ck_assert_str_ne(copy_of_hash, plaintext_password);
    
    // Default values should be initialized to 0
    ck_assert_int_eq(res->login_count, 0);
    ck_assert_int_eq(res->login_fail_count, 0);
    ck_assert_int_eq(res->last_login_time, 0);
    
    // Account ID should be non-zero
    // ck_assert_int_ne(res->account_id, 0);
    
    // Clean up
    account_free(res);
    printf("Test passed: account_create works correctly\n");

#test test_account_create_invalid_params
    print_test_starting("test_account_create_invalid_params");
    
    // Test null parameters
    account_t *res = account_create(NULL, "password", "email@test.com", "1990-01-01");
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user", NULL, "email@test.com", "1990-01-01");
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user", "password", NULL, "1990-01-01");
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user", "password", "email@test.com", NULL);
    ck_assert_ptr_eq(res, NULL);
    
    // Test invalid userid
    res = account_create("", "password", "email@test.com", "1990-01-01");
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user with spaces", "password", "email@test.com", "1990-01-01");
    ck_assert_ptr_eq(res, NULL);
    
    // Test invalid birthdates
    res = account_create("user", "password", "email@test.com", "invalid");
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user", "password", "email@test.com", "1800-01-01"); // Before 1900
    ck_assert_ptr_eq(res, NULL);
    
    res = account_create("user", "password", "email@test.com", "2200-01-01"); // After 2100
    ck_assert_ptr_eq(res, NULL);
    
    printf("Test passed: account_create validates parameters correctly\n");

#tcase account_update_password_test_case

#test test_account_update_password_neq_plaintext
    print_test_starting("test_account_update_password_neq_plaintext");
    
    account_t acc = { 0 };
    const char* plaintext_password = "password123";

    bool result = account_update_password(&acc, plaintext_password);
    ck_assert_int_eq(result, 1);

    char copy_of_hash[HASH_LENGTH + 1] = { 0 };
    memcpy(copy_of_hash, acc.password_hash, HASH_LENGTH);
    
    // Password hash should not match plaintext
    ck_assert_str_ne(copy_of_hash, plaintext_password);
    
    printf("Test passed: account_update_password does not store plaintext\n");

#test test_account_validate_password_ok
    print_test_starting("test_account_validate_password_ok");
    
    account_t acc = { 0 };
    const char* plaintext_password = "password123";

    bool result = account_update_password(&acc, plaintext_password);
    ck_assert_int_eq(result, 1);

    // Validate with correct password
    result = account_validate_password(&acc, plaintext_password);
    ck_assert_int_eq(result, 1);
    
    // Validate with incorrect password
    result = account_validate_password(&acc, "wrong_password");
    ck_assert_int_eq(result, 0);
    
    printf("Test passed: account_validate_password correctly verifies passwords\n");

#test test_random_salt_generation
    print_test_starting("test_random_salt_generation");

    account_t *acc = account_create("testuser", "repeated_password", "test@example.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);

    // Hash password using Argon2id
    bool result = account_update_password(acc, "repeated_password");
    ck_assert_int_eq(result, 1);

    // Store original password hash and ensure NULL termination
    char old_password_hash[HASH_LENGTH];
    strncpy(old_password_hash, acc->password_hash, HASH_LENGTH - 1);
    old_password_hash[HASH_LENGTH - 1] = '\0';

    result = account_update_password(acc, "repeated_password");
    ck_assert_int_eq(result, 1);

    // Store new password hash for same password and ensure NULL termination
    char new_password_hash[HASH_LENGTH];
    strncpy(new_password_hash, acc->password_hash, HASH_LENGTH - 1);
    new_password_hash[HASH_LENGTH - 1] = '\0';

    int comp_result = strncmp(old_password_hash, new_password_hash, HASH_LENGTH - 1);

    ck_assert_int_ne(comp_result, 0);

    printf("Test passed: account_update_password correctly salts passwords\n");

#tcase account_login_tracking_test_case

#test test_account_login_tracking
    print_test_starting("test_account_login_tracking");
    
    // Create test account
    account_t *acc = account_create("testuser", "password123", "test@example.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Initial state
    ck_assert_int_eq(acc->login_count, 0);
    ck_assert_int_eq(acc->login_fail_count, 0);
    ck_assert_int_eq(acc->last_login_time, 0);
    
    // Record failed login
    account_record_login_failure(acc);
    ck_assert_int_eq(acc->login_fail_count, 1);
    ck_assert_int_eq(acc->login_count, 0); // Should not change
    
    // Record successful login
    ip4_addr_t ip = 0x01020304; // 1.2.3.4
    account_record_login_success(acc, ip);
    ck_assert_int_eq(acc->login_count, 1);
    ck_assert_int_eq(acc->login_fail_count, 0); // Should be reset
    ck_assert_int_ne(acc->last_login_time, 0); // Should be updated
    ck_assert_int_eq(acc->last_ip, ip);
    
    // Clean up
    account_free(acc);
    printf("Test passed: account login tracking works correctly\n");

#tcase account_ban_expire_test_case

#test test_account_ban_expire
    print_test_starting("test_account_ban_expire");
    
    // Create test account
    account_t *acc = account_create("testuser2", "password123", "test2@example.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);   

    // Initial state - not banned or expired
    ck_assert_int_eq(account_is_banned(acc), 0);
    ck_assert_int_eq(account_is_expired(acc), 0);
    
    // Ban account for 60 seconds
    time_t now = time(NULL);
    time_t ban_time = now + 60;
    account_set_unban_time(acc, ban_time);
    
    // Should be banned
    ck_assert_int_eq(account_is_banned(acc), 1);
    
    // Unban
    account_set_unban_time(acc, 0);
    ck_assert_int_eq(account_is_banned(acc), 0);
    
    // Set to expire in 60 seconds
    time_t expire_time = now + 60;
    account_set_expiration_time(acc, expire_time);
    
    // Should not be expired yet
    ck_assert_int_eq(account_is_expired(acc), 0);
    
    // Expire account
    account_set_expiration_time(acc, now - 1);
    ck_assert_int_eq(account_is_expired(acc), 1);
    
    // Clean up
    account_free(acc);
    printf("Test passed: account ban and expiration functions work correctly\n");

#tcase account_email_test_case

#test test_account_set_email
    print_test_starting("test_account_set_email");
    
    // Create test account
    account_t *acc = account_create("emailuser", "password123", "old@example.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Test valid email update
    const char* new_email = "new@example.com";
    account_set_email(acc, new_email);
    ck_assert_str_eq(acc->email, new_email);
    
    // Test invalid email formats (note: these may vary based on your implementation)
    const char* old_email = new_email;
    
    account_set_email(acc, "invalid"); // No @ symbol
    ck_assert_str_eq(acc->email, old_email); // Should not change
    
    account_set_email(acc, "@nodomain.com"); // Missing username part
    ck_assert_str_eq(acc->email, old_email); // Should not change
    
    account_set_email(acc, "noat.com"); // No @ symbol
    ck_assert_str_eq(acc->email, old_email); // Should not change
    
    account_set_email(acc, "user@"); // Missing domain
    ck_assert_str_eq(acc->email, old_email); // Should not change
    
    // Clean up
    account_free(acc);
    printf("Test passed: account_set_email validates properly\n");

#tcase account_print_summary_test_case

#test test_account_print_summary
    print_test_starting("test_account_print_summary");
    
    // Create test account with some activity
    account_t *acc = account_create("summaryuser", "password123", "summary@example.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Add some activity
    ip4_addr_t ip = 0x0A0B0C0D; // 10.11.12.13
    account_record_login_success(acc, ip);
    
    // Create a temporary file
    char filename[] = "/tmp/account_summary_test";
    FILE *fp = fopen(filename, "w+");
    ck_assert_ptr_ne(fp, NULL);
    int fd = fileno(fp);
    
    // Print summary to file
    bool result = account_print_summary(acc, fd);
    ck_assert_int_eq(result, 1);
    
    // Rewind file for reading
    rewind(fp);
    
    // Read contents (simple test - just check we have some content)
    char buffer[1024] = {0};
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, fp);
    ck_assert_int_gt((int)bytes_read, 0);
    
    // Close and remove temp file
    fclose(fp);
    remove(filename);
    
    // Verify summary contains expected fields
    ck_assert_ptr_ne(strstr(buffer, "User ID: summaryuser"), NULL);
    ck_assert_ptr_ne(strstr(buffer, "Email: summary@example.com"), NULL);
    
    // Clean up
    account_free(acc);
    printf("Test passed: account_print_summary works correctly\n");

    #test test_account_create_validates_birthdate_format
    print_test_starting("test_account_create_validates_birthdate_format");
    
    // Test invalid date formats
    account_t *res1 = account_create("user1", "password", "email@test.com", "19900101"); // No hyphens
    ck_assert_ptr_eq(res1, NULL);
    
    account_t *res2 = account_create("user2", "password", "email@test.com", "1990/01/01"); // Wrong separator
    ck_assert_ptr_eq(res2, NULL);
    
    // Test invalid dates
    account_t *res3 = account_create("user3", "password", "email@test.com", "1990-02-30"); // Invalid day for Feb
    ck_assert_ptr_eq(res3, NULL);
    
    account_t *res4 = account_create("user4", "password", "email@test.com", "1990-13-01"); // Invalid month
    ck_assert_ptr_eq(res4, NULL);
    
    printf("Test passed: account_create correctly validates birthdate format\n");

#test test_account_nullsafe_free
    print_test_starting("test_account_nullsafe_free");
    
    // Test with NULL pointer - should not crash
    account_free(NULL);
    
    // Test with valid account
    account_t *acc = account_create("freetest", "password", "free@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    account_free(acc);
    
    printf("Test passed: account_free safely handles NULL and valid accounts\n");

#test test_account_email_validation
    print_test_starting("test_account_email_validation");
    
    account_t *acc = account_create("emailtest", "password", "valid@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Test various invalid email formats
    account_set_email(acc, "missing_at_symbol.com");
    ck_assert_str_eq(acc->email, "valid@test.com"); // Should not change
    
    account_set_email(acc, "@no_username.com");
    ck_assert_str_eq(acc->email, "valid@test.com"); // Should not change
    
    account_set_email(acc, "no_domain@");
    ck_assert_str_eq(acc->email, "valid@test.com"); // Should not change
    
    // Test valid email update
    account_set_email(acc, "new_valid@example.org");
    ck_assert_str_eq(acc->email, "new_valid@example.org"); // Should change
    
    account_free(acc);
    printf("Test passed: account_set_email properly validates email formats\n");

#test test_ban_functionality
    print_test_starting("test_ban_functionality");
    
    account_t *acc = account_create("bantest", "password", "ban@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Initially not banned
    ck_assert_int_eq(account_is_banned(acc), 0);
    
    // Set ban time to future
    time_t now = time(NULL);
    time_t future = now + 3600; // 1 hour from now
    account_set_unban_time(acc, future);
    
    // Should be banned
    ck_assert_int_eq(account_is_banned(acc), 1);
    
    // Set ban time to past
    account_set_unban_time(acc, now - 3600); // 1 hour ago
    
    // Should not be banned
    ck_assert_int_eq(account_is_banned(acc), 0);
    
    account_free(acc);
    printf("Test passed: Ban functionality works correctly\n");

#test test_expiration_functionality
    print_test_starting("test_expiration_functionality");
    
    account_t *acc = account_create("expiretest", "password", "expire@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Initially not expired
    ck_assert_int_eq(account_is_expired(acc), 0);
    
    // Set expiration to future
    time_t now = time(NULL);
    time_t future = now + 3600; // 1 hour from now
    account_set_expiration_time(acc, future);
    
    // Should not be expired yet
    ck_assert_int_eq(account_is_expired(acc), 0);
    
    // Set expiration to past
    account_set_expiration_time(acc, now - 3600); // 1 hour ago
    
    // Should be expired
    ck_assert_int_eq(account_is_expired(acc), 1);
    
    account_free(acc);
    printf("Test passed: Expiration functionality works correctly\n");

#test test_login_record_functionality
    print_test_starting("test_login_record_functionality");
    
    account_t *acc = account_create("recordtest", "password", "record@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Test initial state
    ck_assert_int_eq(acc->login_count, 0);
    ck_assert_int_eq(acc->login_fail_count, 0);
    ck_assert_int_eq(acc->last_login_time, 0);
    
    // Test login failure recording
    account_record_login_failure(acc);
    ck_assert_int_eq(acc->login_fail_count, 1);
    ck_assert_int_eq(acc->login_count, 0); // Should not change
    
    // Test login success recording
    ip4_addr_t test_ip = 0x12345678; // 18.52.86.120
    account_record_login_success(acc, test_ip);
    ck_assert_int_eq(acc->login_count, 1);
    ck_assert_int_eq(acc->login_fail_count, 0); // Should be reset
    ck_assert_int_ne(acc->last_login_time, 0); // Should be updated
    ck_assert_int_eq(acc->last_ip, test_ip);
    
    account_free(acc);
    printf("Test passed: Login recording functions work correctly\n");

#test test_password_handling
    print_test_starting("test_password_handling");
    
    account_t *acc = account_create("pwtest", "initial_password", "pw@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Should validate with correct password
    ck_assert_int_eq(account_validate_password(acc, "initial_password"), 1);
    
    // Should fail with incorrect password
    ck_assert_int_eq(account_validate_password(acc, "wrong_password"), 0);
    
    // Update password
    bool result = account_update_password(acc, "new_password");
    ck_assert_int_eq(result, 1);
    
    // Should validate with new password
    ck_assert_int_eq(account_validate_password(acc, "new_password"), 1);
    
    // Should fail with old password
    ck_assert_int_eq(account_validate_password(acc, "initial_password"), 0);
    
    account_free(acc);
    printf("Test passed: Password handling functions work correctly\n");

    #test test_print_summary_functionality
    print_test_starting("test_print_summary_functionality");
    
    // Create account with some activity
    account_t *acc = account_create("summarytest", "password", "summary@test.com", "1990-01-01");
    ck_assert_ptr_ne(acc, NULL);
    
    // Set some values
    account_record_login_success(acc, 0x01020304);
    
    // Create temp file for testing
    char filename[] = "/tmp/account_test_summary";
    FILE *file = fopen(filename, "w+");
    ck_assert_ptr_ne(file, NULL);
    int fd = fileno(file);
    
    // Print summary
    bool result = account_print_summary(acc, fd);
    ck_assert_int_eq(result, 1);
    
    // Rewind and read file
    rewind(file);
    
    char buffer[1024] = {0};
    size_t read_bytes = fread(buffer, 1, sizeof(buffer)-1, file);
    ck_assert_int_gt((int)read_bytes, 0);
    
    // Check for expected content
    ck_assert_ptr_ne(strstr(buffer, "User ID: summarytest"), NULL);
    
    fclose(file);
    remove(filename);  // Use remove instead of unlink
    account_free(acc);
    printf("Test passed: account_print_summary produces expected output\n");

    #test test_login_success_scenario
    print_test_starting("test_login_success_scenario");
    
    const char *userid = "loginuser";
    const char *password = "login_password";
    ip4_addr_t client_ip = 0x01020304;
    
    // Create test account for login test
    account_t *test_account = account_create(userid, password, "login@test.com", "1990-01-01");
    ck_assert_ptr_ne(test_account, NULL);
    
    // Use account_validate_password to simulate the login process
    bool password_valid = account_validate_password(test_account, password);
    ck_assert_int_eq(password_valid, 1);
    
    // Verify account is not banned or expired
    ck_assert_int_eq(account_is_banned(test_account), 0);
    ck_assert_int_eq(account_is_expired(test_account), 0);
    
    // Record successful login
    account_record_login_success(test_account, client_ip);
    
    // Verify login was recorded
    ck_assert_int_eq(test_account->login_count, 1);
    ck_assert_int_eq(test_account->login_fail_count, 0);
    ck_assert_int_eq(test_account->last_ip, client_ip);
    
    account_free(test_account);
    printf("Test passed: Login success scenario works correctly\n");

#test test_login_failure_handling
    print_test_starting("test_login_failure_handling");
    
    account_t *test_account = account_create("failuser", "correct_password", "fail@test.com", "1990-01-01");
    ck_assert_ptr_ne(test_account, NULL);
    
    // Attempt with wrong password
    bool password_valid = account_validate_password(test_account, "wrong_password");
    ck_assert_int_eq(password_valid, 0);
    
    // Record failed login
    account_record_login_failure(test_account);
    
    // Verify failure was recorded
    ck_assert_int_eq(test_account->login_fail_count, 1);
    ck_assert_int_eq(test_account->login_count, 0); // Should not change
    
    // Multiple failures
    account_record_login_failure(test_account);
    account_record_login_failure(test_account);
    ck_assert_int_eq(test_account->login_fail_count, 3);
    
    // Successful login resets failure count
    password_valid = account_validate_password(test_account, "correct_password");
    ck_assert_int_eq(password_valid, 1);
    account_record_login_success(test_account, 0x01020304);
    ck_assert_int_eq(test_account->login_fail_count, 0);
    
    account_free(test_account);
    printf("Test passed: Login failure handling works correctly\n");

#test test_account_id_ok
    print_test_starting("test_account_id_ok");
    
    // Perform multiple account_create calls
    account_t *test_account0 = account_create("user0", "password", "123@test.com", "1990-01-01");
    ck_assert_ptr_ne(test_account0, NULL);

    account_t *test_account1 = account_create("user1", "password", "123@test.com", "1990-01-01");
    ck_assert_ptr_ne(test_account1, NULL);

    account_t *test_account2 = account_create("user2", "password", "123@test.com", "1990-01-01");
    ck_assert_ptr_ne(test_account2, NULL);

    // Verify unique, incremenenting IDs
    ck_assert_int_eq(test_account0->account_id, 0);
    ck_assert_int_eq(test_account1->account_id, 1);
    ck_assert_int_eq(test_account2->account_id, 2);

    account_free(test_account0);
    account_free(test_account1);
    account_free(test_account2);
    printf("Test passed: Account ID incrementation works correctly\n");

// vim: syntax=c :